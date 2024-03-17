import asyncio
import json
import logging
import os
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Any, Optional, Union

import yara
from oletools import rtfobj
from oletools.oleid import OleID
from oletools.olevba import VBA_Parser
from PyPDF2 import PdfReader

exif_tool_path = "bins/exiftool.exe"


def extract_ole_features(
    metadata: dict[str, Any],
    output_directory: str,
    filename="oletool_features_updated.json",
) -> None:
    """Extracts the OLE features from a given file and writes them to a JSON file.

    Args:
        metadata (dict): The metadata of the file.
        output_directory (str): The directory to write the JSON file to.
        filename (str, optional): The name of the JSON file to write the OLE features to. Defaults to "oletool_features_updated.json".
    """
    file_path = os.path.join(output_directory, filename)
    if os.path.exists(file_path):
        return

    ole_features = defaultdict(dict)
    sample_hash = os.path.basename(os.path.normpath(output_directory))
    file_type = metadata.get("FileType", "")

    if not is_supported_file_type(file_type):
        logging.info(f"Unsupported file type for {output_directory}.")
        return
    file_to_process = os.path.join(output_directory, sample_hash)
    try:
        ole_features[sample_hash] = extract_features_from_file(
            file_to_process, file_type=file_type
        )
        if ole_features[sample_hash]:
            write_features_to_file(ole_features, file_path)
    except Exception as e:
        logging.info(f"Exception occurred for sample {output_directory}: {e}")
        if ole_features:
            write_features_to_file(ole_features, file_path)


def is_supported_file_type(file_type: str) -> bool:
    """Checks if the file type is supported for OLE feature extraction.

    Args:
        file_type (str): The file type of the file based on exif.

    Returns:
        bool: True if the file type is supported, False otherwise.
    """
    supported_types = [
        "DOC",
        "DOCX",
        "DOTM",
        "PPT",
        "PDF",
        "RTF",
        "XLS",
        "XLSX",
        "FPX",
        "ZIP",
    ]
    return file_type in supported_types


def extract_features_from_file(file: str, file_type: str) -> dict[str, Any]:
    """Extracts features from a file based on its metadata.

    Args:
        file (str): The path to the file.
        file_type (str): The file type of the file based on exif.

    Returns:
        dict: The features extracted from the file.
    """
    features = {}
    if file_type == "RTF":
        features.update(extract_rtf_features(file))
    if file_type == "PDF":
        features.update(pdf_feature(file))
    if file_type not in ["RTF", "PDF"]:
        oid = OleID(file)
        indicators = oid.check()
        for indicator in indicators:
            if isinstance(indicator.value, (bytes, bytearray)):
                features[indicator.name] = indicator.value.decode("latin-1")
            else:
                features[indicator.name] = indicator.value

        vba_features = extract_vba_features(file)
        for key in vba_features:
            features[key] = vba_features.get(key)
    return features


def extract_rtf_features(file: str) -> dict[str, str]:
    """Extracts features from an RTF file.
    Args:
        file (str): The path to the RTF file.
    Returns:
        dict: The features extracted from the RTF file.
    """
    features = {"rtfobject": {}}
    for index, orig_len, data in rtfobj.rtf_iter_objects(file):
        features["rtfobject"][hex(index)] = f"size {len(data)}"
    return features


def extract_vba_features(file: str) -> dict[str, Any]:
    """Extracts VBA features from a file.

    Args:
        file (str): The path to the file.
    Returns:
        dict: The VBA features extracted from the file.
    """
    vbaparser = VBA_Parser(file)
    if not vbaparser.detect_vba_macros():
        logging.info(f"The file {file} doesn't have VBA macros.")
        return {}

    features = {"VBAMacro": defaultdict(list)}
    for filename, stream_path, vba_filename, vba_code in vbaparser.extract_macros():
        features["VBAMacro"]["Filename"].append(filename)
        features["VBAMacro"]["OLEstream"].append(stream_path)
        features["VBAMacro"]["VBAfilename"].append(vba_filename)
        features["VBAMacro"]["VBAcode"].append(vba_code)

    results = vbaparser.analyze_macros()
    for kw_type, keyword, description in results:
        features["VBAMacro"]["Keyword Types"].append(kw_type)
        if features.get("Keyword Found"):
            features["Keyword Found"].setdefault(keyword, description)
        else:
            features["Keyword Found"] = {keyword: description}

    features["VBAMacro"].update(
        {
            "AutoExec keywords": vbaparser.nb_autoexec,
            "Suspicious keywords": vbaparser.nb_suspicious,
            "IOCs": vbaparser.nb_iocs,
            "Hex obfuscated strings": vbaparser.nb_hexstrings,
            "Base64 obfuscated strings": vbaparser.nb_base64strings,
            "Dridex obfuscated strings": vbaparser.nb_dridexstrings,
            "VBA obfuscated strings": vbaparser.nb_vbastrings,
        }
    )
    return features


def write_features_to_file(features, file_path) -> None:
    """Writes the extracted features to a JSON file.

    Args:
        features (dict): The extracted features.
        file_path (str): The path to the JSON file.

    """
    with open(file_path, "w+") as f:
        json.dump(features, f, indent=4)


def extract_pdf_metadata(reader):
    """Extracts metadata from a PDF file.

    Args:
        reader (PdfReader): A PdfReader object of the PDF file.

    Returns:
        dict: A dictionary containing the PDF metadata.
    """
    metadata = reader.metadata
    return {
        "Number of Pages": len(reader.pages),
        "Author": getattr(metadata, "author", None),
        "Creator": getattr(metadata, "creator", None),
        "Producer": getattr(metadata, "producer", None),
        "Subject": getattr(metadata, "subject", None),
        "Title": getattr(metadata, "title", None),
    }


def extract_pdf_text(page):
    """Extracts text from the first page of a PDF file.

    Args:
        page (PageObject): The first page object of the PDF.

    Returns:
        str: Extracted text from the first page of the PDF.
    """
    try:
        return page.extract_text() or "No text found"
    except Exception as e:
        logging.warning(f"Failed to extract text: {e}")
        return "Failed to extract text"


def pdf_feature(file_name):
    """Extracts features from a PDF file including metadata and text from the first page.

    Args:
        file_name (str): The path to the PDF file.

    Returns:
        defaultdict: A dictionary containing extracted features and information.
    """
    feature_set = defaultdict(dict)

    try:
        reader = PdfReader(file_name)
        first_page = reader.pages[0] if reader.pages else None

        if first_page:
            feature_set["Page"]["Text"] = extract_pdf_text(first_page)

        feature_set["Information"] = extract_pdf_metadata(reader)

    except Exception as e:
        logging.warning(f"Warning: Exception occurred {e}")
        feature_set["Exception"] = str(e)

    return feature_set


def get_exiftool_json(
    file_path: str, parsing_charset: str = "latin1"
) -> Optional[Union[dict[str, Any], None]]:
    """
    Get Exiftool output in JSON format for a given file with a specific charset (Latin-1).

    Parameters:
        file_path (str): The path to the file.
        parsing_charset: What encoding to process the file with

    Returns:
        dict or None: A dictionary containing the Exiftool information in JSON format,
                    or None if an error occurs.
    """
    try:
        exiftool_command = [
            exif_tool_path,
            "-j",
            "-charset",
            parsing_charset,
            file_path,
        ]
        exiftool_output = subprocess.check_output(
            exiftool_command, universal_newlines=True, encoding=parsing_charset
        )
        exif_data = json.loads(exiftool_output)[0]
        return exif_data
    except subprocess.CalledProcessError as e:
        logging.debug(f"Error handling output from subprocess: {e}")
        return None
    except Exception as all_other_exceptions:
        logging.debug(f"Error running Exiftool: {all_other_exceptions}")
        return None


def process_document_file(file_path: str, output_directory: str) -> None:
    """
    Process a file to extract OLE features and write them to a JSON file.

    Examples:
        >>> process_document_file(r"C:/users/randomuser/5aaaaaaaaabbb/5aaaaaaaaabbb", r"C:/users/randomuser/5aaaaaaaaabbb")
        >>> process_document_file(r"C:/users/randomuser/6aaa8845ssscc/6aaa8845ssscc", r"C:/users/randomuser/6aaa8845ssscc")

    Args:
        file_path (str): The path to the file.
        output_directory (str): The directory to write the JSON file to.
    """
    metadata = get_exiftool_json(file_path)
    if metadata:
        extract_ole_features(metadata, output_directory)


def process_yara_rule(
    file_path: str,
    yara_rules_path: str,
    output_dir: str = None,
    result_filename: str = "malcatYaraResults.json",
) -> None:
    """
    Applies YARA rules to a specified file and saves the matches in a JSON file.

    Examples:
        >>> process_yara_rule("C:/users/randomuser/5aaaaaaaaabbb/5aaaaaaaaabbb", "yara_rules/malcat.yar", "C:/users/randomuser/5aaaaaaaaabbb")
        >>> process_yara_rule("C:/users/randomuser/6aaa8845ssscc/6aaa8845ssscc", "yara_rules/malcat.yar", "C:/users/randomuser/6aaa8845ssscc")

    Args:
        file_path: Path to the file to be scanned.
        yara_rules_path: Path to the YARA rules file.
        output_dir: Directory to save the results JSON file to.
        result_filename: Name of the JSON file to save the results to. Defaults to "malcatYaraResults.json".
    """
    # Compile YARA rules from the specified file path
    rules = yara.compile(
        filepath=yara_rules_path, includes=True, error_on_warning=False
    )

    try:
        matches = rules.match(file_path)
        yara_match = {"hash": os.path.basename(os.path.normpath(file_path))}

        # Store each match in the dictionary
        for match in matches:
            yara_match[str(match)] = True

        # Determine the path for the results JSON file
        result_path = os.path.join(output_dir, result_filename)

        # Write the matches to the specified JSON file
        with open(result_path, "w+") as f:
            json.dump(yara_match, f, indent=4)

    except Exception as e:
        logging.error(
            f"Error extracting the yara rules for the file path {file_path}: {e}"
        )


async def process_floss_file(
    file_path: str,
    output_directory: str,
    floss_executable: str = "floss2.2.exe",
    out_file_name: str = "flossresults_reduced_7.json",
) -> None:
    """
    Executes FLOSS on a specified file and saves the output to a JSON file.

    Examples:
        asyncio.run(process_floss_file(r"C:\\Users\\ExampleUser\\Documents\\ThreatReportSamples\\sample.exe",
                           r"C:\\Users\\ExampleUser\\Documents\\OutputDirectory",
                           "bins/floss2.2.exe",
                           "flossresults_reduced_7.json"))

    Args:
        file_path: The full path to the file to be processed.
        output_directory: The directory where the output file should be saved.
        floss_executable: The path to the FLOSS executable. Defaults to "floss2.2.exe".
        out_file_name: The name of the output JSON file. Defaults to "flossresults_reduced_7.json".
    """
    if not os.path.isfile(file_path):
        logging.error(f"File does not exist: {file_path}")
        return

    # Ensure the output directory exists
    if not os.path.exists(output_directory):
        os.makedirs(output_directory, exist_ok=True)

    path_to_out_file = os.path.join(output_directory, out_file_name)
    command = f'powershell {floss_executable} --json -n 7 -o "{path_to_out_file}" --no stack tight decoded -- "{file_path}"'

    process = await asyncio.create_subprocess_shell(
        command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )

    _, stderr = await process.communicate()
    if stderr:
        logging.error(f"Error while processing floss on file: {file_path}: {stderr}")

    logging.info(f"Command output for file {os.path.basename(file_path)}:")


# # Example usage
# root_dir = r"C:\Users\ricewater\Documents\TestCorpus\0a9c88d03260b92608c9c079a1b449cf46e5cd764f12f2ec852038dd6bd0fa97"
# sample_file_path = os.path.join(root_dir, "0a9c88d03260b92608c9c079a1b449cf46e5cd764f12f2ec852038dd6bd0fa97")
# floss_executable_path = "bins/floss2.2.exe"

# # Run the process_file function with asyncio's event loop
# asyncio.run(process_floss_file(sample_file_path, root_dir, floss_executable_path))
