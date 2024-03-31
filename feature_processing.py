import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, Optional, Union


import aiofiles
import lief
import yara
from oletools import rtfobj
from oletools.oleid import OleID
from oletools.olevba import VBA_Parser
from PyPDF2 import PdfReader

logger = logging.getLogger(__name__)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

exif_tool_path = "bins/exiftool.exe"


def extract_ole_features(
    metadata: dict[str, Any],
    output_directory: str,
    filename: str = "oletool_features_updated.json",
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
        raise e
        logging.debug(f"Error handling output from subprocess: {e}")
        return None
    except Exception as all_other_exceptions:
        raise all_other_exceptions
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
    output_dir: str,
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
        logging.error(f"Error while processing floss on file: {file_path!r}: {stderr!r}")

    logging.info(f"Command output for file {os.path.basename(file_path)}:")


def process_exiftool(
    file_path: str,
    output_directory: str,
    encoding: str = "latin1",
    output_file_name: str = "exiftool_results.json",
) -> Optional[dict[str, Any]]:
    """
    Process a file to extract metadata using Exiftool and write it to a JSON file.

    Examples:
        >>> process_exiftool(r"C:/users/randomuser/5aaaaaaaaabbb/5aaaaaaaaabbb", r"C:/users/randomuser/5aaaaaaaaabbb")
        >>> process_exiftool(r"C:/users/randomuser/6aaa8845ssscc/6aaa8845ssscc", r"C:/users/randomuser/6aaa8845ssscc")

    Args:
        file_path (str): The path to the file.
        output_directory (str): The directory to write the JSON file to.
        encoding (str): The encoding to use when processing the file. Defaults to "latin1".
        output_file_name (str): The name of the JSON file to write the Exiftool results to. Defaults to "exiftool_results.json".
    """
    metadata = get_exiftool_json(file_path, encoding)
    if metadata:
        write_features_to_file(
            metadata, os.path.join(output_directory, output_file_name)
        )
    return metadata


from collections import defaultdict
from datetime import datetime

import lief


def from_timestamp_to_date(timestamp: int) -> str:
    """
    Converts a timestamp into a printable date string.

    Args:
        timestamp (int): Timestamp to be converted.

    Returns:
        str: Formatted date string (e.g., "Jan 01 2019 at 00:00:00").
    """
    if not timestamp:
        return None
    return datetime.utcfromtimestamp(timestamp).strftime("%b %d %Y at %H:%M:%S")


def extract_common_attributes(binary: Any, feature_set: dict, file_type: str):
    """
    Extracts common attributes from the binary file and updates the feature set to include
    platform, CPU type, file type, entrypoint, and the number of sections.

    This version is compatible with PE, ELF, and Mach-O binary types, accommodating the differences
    in their attribute names and structures.

    Args:
        binary: The binary file being processed, expected to be an instance from lief.
        feature_set (defaultdict[list]): The feature set to update with the extracted attributes.
        file_type (str): The type of the file (e.g., 'PE', 'ELF', 'MachO').
    """
    feature_set["Platform"] = file_type

    # Handling CPU type variations
    cpu_type_attr = (
        getattr(binary.header, "cpu_type", None)
        or getattr(binary.header, "machine", None)
        or getattr(binary.header, "machine_type", None)
    )
    feature_set["CPU type"] = str(cpu_type_attr) if cpu_type_attr else "Unknown"

    # Handling file type if applicable
    file_type_attr = getattr(binary.header, "file_type", None)
    feature_set["File type"] = str(file_type_attr) if file_type_attr else "Unknown"

    # Entrypoint, if available
    if hasattr(binary, "entrypoint"):
        feature_set["Entrypoint"] = binary.entrypoint

    # Number of sections
    number_of_sections_attr = getattr(binary.header, "numberof_sections", None)
    if number_of_sections_attr is not None:
        feature_set["Number of sections"] = number_of_sections_attr


def lief_header(binary, file_type: str) -> dict:
    """
    Displays header information for ELF, PE, and Mach-O files.

    Args:
        binary: The binary file to process.
        file_type (str): The type of the binary file.

    Returns:
        dict: A dictionary containing the extracted features.
    """
    feature_set = dict()
    extract_common_attributes(binary, feature_set, file_type)

    if file_type == "machofile":
        feature_set.update(extract_macho_attributes(binary))
    if file_type in ["EXEfile", "DLLfile"]:
        feature_set.update(extract_pe_attributes(binary))
    if file_type == "elffile":
        feature_set.update(extract_elf_attributes(binary))

    if not feature_set:
        print("Warning: No header found for the specified file type.")
    return feature_set


def extract_macho_attributes(binary: lief.MachO.Binary) -> dict:
    """
    Extracts Mach-O specific attributes from the binary file.

    Args:
        binary: The Mach-O binary file to process.

    Returns:
        A dictionary containing the extracted Mach-O attributes.
    """
    feature_set = {}
    feature_set["CPU type"] = str(binary.header.cpu_type)
    feature_set["File type"] = str(binary.header.file_type)
    feature_set["Number of commands"] = binary.header.nb_cmds
    feature_set["Size of commands"] = binary.header.sizeof_cmds
    feature_set["Flags"] = ":".join(str(flag) for flag in binary.header.flags_list)
    return feature_set


def resolve_attribute_value(value: Any) -> Union[dict, list, str, int, float, None]:
    """Attempts to resolve the value of attributes, handling specific types to include names and values in a dict.

    Args:
        value: The value to resolve.

    Returns:
        The resolved value, which could be a primitive type, string representation, a dictionary, or a list of dictionaries.
    """
    if isinstance(value, (list, set)):
        # Handle lists or sets, assuming they contain objects that can be resolved to name-value pairs
        return [
            {item.name: item.value}
            for item in value
            if hasattr(item, "name") and hasattr(item, "value")
        ]
    elif hasattr(value, "name") and hasattr(value, "value"):
        # Handle single objects that can be resolved to name-value pairs
        return {value.name: value.value}
    else:
        return value


def extract_pe_attributes(binary: lief.PE.Binary) -> dict:
    """Extracts PE specific attributes from the binary file, handling specific complex types.

    Args:
        binary: The PE binary file to process.

    Returns:
        A dictionary containing the extracted PE attributes, properly handling complex or enumerable types.
    """
    feature_set = {
        "Date of compilation": from_timestamp_to_date(binary.header.time_date_stamps),
        "Imphash": lief.PE.get_imphash(binary),
    }

    # Handle optional header specific attributes, resolving complex or enumerable types
    if binary.header.sizeof_optional_header > 0:
        optional_header_attrs = {}
        for key in dir(binary.optional_header):
            if not key.startswith("_"):  # Skip private attributes
                raw_value = getattr(binary.optional_header, key, None)
                value = resolve_attribute_value(raw_value)
                # Check to ensure the value is serializable (now including dicts and lists of dicts)
                if isinstance(value, (str, int, float, dict, list)):
                    optional_header_attrs[key] = value
        feature_set["Optional header"] = optional_header_attrs

    return feature_set


def extract_elf_attributes(binary: lief.ELF.Binary) -> dict:
    """
    Extracts ELF-specific attributes from an ELF binary file.

    Args:
        binary: The ELF binary file being processed.

    Returns:
        A dictionary containing the extracted ELF attributes.
    """
    feature_set = {}

    # Direct attribute extraction with straightforward mapping
    feature_set["Platform"] = "ELF"
    feature_set["Magic"] = bytes(binary.header.identity).hex()
    feature_set["Type"] = str(binary.header.file_type)
    feature_set["Entrypoint"] = hex(binary.header.entrypoint)
    feature_set["ImageBase"] = hex(binary.imagebase) if binary.imagebase else "-"
    feature_set["Header size"] = binary.header.header_size
    feature_set["Endianness"] = str(binary.header.identity_data)
    feature_set["Class"] = str(binary.header.identity_class)
    feature_set["OS/ABI"] = str(binary.header.identity_os_abi)
    feature_set["Version"] = str(binary.header.identity_version)
    feature_set["Architecture"] = str(binary.header.machine_type)

    # Handling ELF-specific flags, such as MIPS Flags, if applicable
    if hasattr(binary.header, "mips_flags_list") and binary.header.mips_flags_list:
        mips_flags = ":".join(str(flag) for flag in binary.header.mips_flags_list)
    else:
        mips_flags = "No flags"
    feature_set["MIPS Flags"] = mips_flags

    # Additional ELF-specific details
    feature_set["Number of sections"] = binary.header.numberof_sections
    feature_set["Number of segments"] = binary.header.numberof_segments
    feature_set["Program header offset"] = hex(binary.header.program_header_offset)
    feature_set["Program header size"] = binary.header.program_header_size
    feature_set["Section Header offset"] = hex(binary.header.section_header_offset)
    feature_set["Section header size"] = binary.header.section_header_size

    return feature_set


def check_binary_format(
    binary,
) -> Literal["DLLfile", "EXEfile", "machofile", "elffile", "null"]:
    """
    Checks the format of a binary file and returns its type as a literal string.

    Args:
        binary: The binary file to check.

    Returns:
        Literal['DLLfile', 'EXEfile', 'machofile', 'elffile', 'null']: A literal string indicating the type of the binary.
    """
    if not binary:
        return "null"

    if binary.format == lief.EXE_FORMATS.PE:
        if binary.header.characteristics & lief.PE.HEADER_CHARACTERISTICS.DLL:
            return "DLLfile"
        else:
            return "EXEfile"
    elif binary.format == lief.EXE_FORMATS.MACHO:
        return "machofile"
    elif binary.format == lief.EXE_FORMATS.ELF:
        return "elffile"

    return "null"


def exported_functions(binary: lief.Binary, file_type: str) -> dict:
    """
    Extracts exported functions from ELF, PE, Mach-O binaries.

    Args:
        binary: The binary file being processed.
        file_type: The type of the binary file.

    Returns:
        A dictionary containing exported functions if any.
    """
    feature_set = {"Exported functions": []}
    if binary.exported_functions:
        for function in binary.exported_functions:
            feature_set["Exported functions"].append(str(function.name))
    else:
        logger.info("Warning: No exported function found")

    return feature_set


def imported_functions(binary: lief.Binary, file_type: str) -> dict:
    """
    Extracts imported functions from ELF, PE, Mach-O binaries.

    Args:
        binary: The binary file being processed.
        file_type: The type of the binary file.

    Returns:
        A dictionary containing imported functions if any.
    """
    feature_set = {"Imported functions": []}
    if binary.imported_functions:
        for function in binary.imported_functions:
            feature_set["Imported functions"].append(str(function.name))
    else:
        logger.info("Warning: No imported function found")

    return feature_set


def print_elf_symbols(symbols: list, title: str) -> dict:
    """
    Formats ELF symbols for display.

    Args:
        symbols: List of symbols.
        title: Title for the display section.

    Returns:
        A dictionary containing formatted ELF symbols.
    """
    feature_set_sub = {
        title: {
            "Name": [],
        }
    }
    if symbols:
        for symbol in symbols:
            feature_set_sub[title]["Name"].append(symbol.name)
    else:
        logger.info(f"Warning: No {title.lower()} found")

    return feature_set_sub


def exported_symbols(binary: lief.Binary, file_type: str) -> dict:
    """
    Extracts exported symbols from ELF, Mach-O binaries.

    Args:
        binary: The binary file being processed.
        file_type: The type of the binary file.

    Returns:
        A dictionary containing exported symbols if any.
    """
    feature_set = {}
    if file_type == "elffile" and binary.exported_symbols:
        feature_set = print_elf_symbols(binary.exported_symbols, "Exported symbols")
    elif file_type == "machofile" and binary.exported_symbols:
        feature_set["Exported symbols"] = {
            "Name": [],
        }
        for symbol in binary.exported_symbols:
            feature_set["Exported symbols"]["Name"].append(symbol.name)
    else:
        logger.info("Warning: No exported symbol found")

    return feature_set


def imported_symbols(binary: lief.Binary, file_type: str) -> dict:
    """
    Extracts imported symbols from ELF, Mach-O binaries.

    Args:
        binary: The binary file being processed.
        file_type: The type of the binary file.

    Returns:
        A dictionary containing imported symbols if any.
    """
    feature_set = {}
    if file_type == "elffile" and binary.imported_symbols:
        feature_set = print_elf_symbols(binary.imported_symbols, "Imported symbols")
    elif file_type == "machofile" and binary.imported_symbols:
        feature_set["Imported symbols"] = {
            "Name": [],
            "Number of sections": [],
            "Value": [],
            "Origin": [],
        }
        for symbol in binary.imported_symbols:
            feature_set["Imported symbols"]["Name"].append(symbol.name)
            feature_set["Imported symbols"]["Number of sections"].append(
                symbol.numberof_sections
            )
            feature_set["Imported symbols"]["Value"].append(hex(symbol.value))
            feature_set["Imported symbols"]["Origin"].append(str(symbol.origin))
    else:
        logger.info("Warning: No imported symbols found")

    return feature_set


def resources(binary: lief.PE.Binary, file_type: str) -> dict:
    """
    Extracts PE resources, if any, from the binary.

    Args:
        binary: The binary file being processed.
        file_type: The type of the binary file, expecting 'EXEfile' or 'DLLfile'.

    Returns:
        A dictionary containing resources information if available.
    """
    feature_set = {}
    if file_type in ["EXEfile", "DLLfile"] and binary.has_resources:
        resource_type = (
            "Directory"
            if binary.resources.is_directory
            else "Data" if binary.resources.is_data else "Unknown"
        )
        feature_set["Resources"] = {
            "Name": binary.resources.name if binary.resources.has_name else "No name",
            "Number of childs": len(binary.resources.childs),
            "Depth": binary.resources.depth,
            "Type": resource_type,
            "Id": hex(binary.resources.id),
        }

        resource_manager = {}
        if binary.resources_manager.has_type:
            resource_manager["Type"] = ", ".join(
                str(rType) for rType in binary.resources_manager.types_available
            )

        if binary.resources_manager.langs_available:
            langs_available = ", ".join(
                str(lang) for lang in binary.resources_manager.langs_available
            )
            sublangs_available = ", ".join(
                str(sublang) for sublang in binary.resources_manager.sublangs_available
            )
            resource_manager.update(
                {"Language": langs_available, "Sub-language": sublangs_available}
            )

        if resource_manager:
            feature_set["Resource manager"] = resource_manager
    else:
        logger.info("Warning: No resource found")

    return feature_set


def dlls(binary: lief.PE.Binary, file_type: str) -> dict:
    """
    Lists the DLLs imported by the PE binary.

    Args:
        binary: The binary file being processed.
        file_type: The type of the binary file, expecting 'EXEfile' or 'DLLfile'.

    Returns:
        A dictionary containing a list of imported libraries if available.
    """
    if file_type in ["EXEfile", "DLLfile"] and binary.libraries:
        return {"Libraries": binary.libraries}
    else:
        logger.info("Error: No dll found")
        return {}


def imports(binary: lief.PE.Binary, file_type: str) -> dict:
    """
    Extracts import information from the PE binary.

    Args:
        binary: The binary file being processed.
        file_type: The type of the binary file, expecting 'EXEfile' or 'DLLfile'.

    Returns:
        A dictionary containing imports names and functions if available.
    """
    feature_set = {
        "Imports Name": [],
        "Imports Function IAT": [],
        "Imports Function name": [],
    }
    if file_type in ["EXEfile", "DLLfile"] and binary.imports:
        for imp in binary.imports:
            feature_set["Imports Name"].append(imp.name)
            for function in imp.entries:
                feature_set["Imports Function IAT"].append(hex(function.iat_address))
                feature_set["Imports Function name"].append(function.name)
    else:
        logger.info("Warning: No import found")

    return feature_set


def load_configuration(binary: lief.PE.Binary, file_type: str) -> dict:
    """
    Extracts load configuration details from the PE binary.

    Args:
        binary: The binary file being processed.
        file_type: The type of the binary file, expecting 'EXEfile' or 'DLLfile'.

    Returns:
        A dictionary containing load configuration details if available.
    """
    if file_type in ["EXEfile", "DLLfile"] and binary.has_configuration:
        config = binary.load_configuration
        return {
            "Configuration": {
                "Version": str(config.version),
                "Characteristics": hex(config.characteristics),
                "Timedatestamp": from_timestamp_to_date(config.timedatestamp),
                "Major version": config.major_version,
                "Minor version": config.minor_version,
                "Security cookie": hex(config.security_cookie),
            }
        }
    else:
        logger.info("Warning: No load configuration found")
        return {}


def signature(pe: lief.PE.Binary, type_of_binary: str) -> dict[str, Any]:
    """
    Extracts and displays the PE signature information, if available.

    Args:
        pe: The PE binary file being processed.
        type_of_binary: The type of the binary file, expecting 'EXEfile' or 'DLLfile'.

    Returns:
        A dictionary containing the signature information if available.
    """
    feature_set = {}
    if type_of_binary in ["EXEfile", "DLLfile"] and pe.has_signatures:
        feature_set["Signature"] = {
            "MD5 authentihash": pe.authentihash_md5.hex(),
            "SHA1 authentihash": pe.authentihash(lief.PE.ALGORITHMS.SHA_1).hex(),
        }

        # Extract signer details from the first signature
        if pe.signatures:
            cert_signer = pe.signatures[0].signers[0].cert
            signer_details = {
                line.split(" : ")[0].strip(): line.split(" : ")[1].strip()
                for line in str(cert_signer).split("\n")
                if " : " in line
            }
            feature_set["Signature"]["Signer details"] = signer_details

    else:
        # Assuming a logging mechanism or similar feedback for when signatures are not found
        print("Warning: No signature found for the specified binary type.")

    return feature_set


def get_sections(binary: lief.Binary, type_of_binary: str) -> dict:
    """
    Extracts and displays the sections of ELF, PE, Mach-O binaries.

    Args:
        binary: The binary file being processed.
        type_of_binary: The type of the binary file ('elffile', 'EXEfile', 'DLLfile', 'machofile').

    Returns:
        A dictionary with sections' details if available.
    """
    sections_info = {"Sections": {}}
    if not binary.sections:
        print("Warning: No section found")
        return sections_info

    rows = []
    if type_of_binary == "elffile":
        for section in binary.sections:
            rows.append(
                {
                    "Name": section.name,
                    "Offset": hex(section.offset),
                    "Virtual address": hex(section.virtual_address),
                    "Size": f"{section.size:<6} bytes",
                    "Type": str(section.type),
                    "Flags": ":".join(str(flag) for flag in section.flags_list),
                    "Entropy": round(section.entropy, 4),
                }
            )
    elif type_of_binary in ["EXEfile", "DLLfile"]:
        for section in binary.sections:
            rows.append(
                {
                    "Name": section.name,
                    "Virtual address": hex(section.virtual_address),
                    "Virtual size": f"{section.virtual_size:<6} bytes",
                    "Offset": hex(section.offset),
                    "Size": f"{section.size:<6} bytes",
                    "Entropy": round(section.entropy, 4),
                }
            )
    elif type_of_binary == "machofile":
        for section in binary.sections:
            rows.append(
                {
                    "Name": section.name,
                    "Virtual address": hex(section.virtual_address),
                    "Type": str(section.type),
                    "Size": f"{section.size:<6} bytes",
                    "Offset": hex(section.offset),
                    "Entropy": round(section.entropy, 4),
                }
            )

    # Updating sections info after processing all sections
    if rows:  # If rows list is not empty, update sections_info
        sections_info["Sections"] = rows

    return sections_info


def code_signature(binary: lief.MachO.Binary, type_of_binary: str) -> dict[str, dict]:
    """
    Extracts and displays the Mach-O code signature if available.

    Args:
      binary: The Mach-O binary file being processed.
      type_of_binary: The type of the binary file, expected to be 'machofile'.

    Returns:
      A dictionary containing code signature details if available.
    """
    if type_of_binary == "machofile" and binary.has_code_signature:
        return {
            "Code signature": {
                "Command": str(binary.code_signature.command),
                "Command offset": hex(binary.code_signature.command_offset),
                "Command size": f"{binary.code_signature.size:<6} bytes",
                "Data offset": hex(binary.code_signature.data_offset),
                "Data size": f"{binary.code_signature.data_size:<6} bytes",
            }
        }
    else:
        logger.info("Warning: No code signature found")
        return {}


def source_version(binary: lief.MachO.Binary, type_of_binary: str) -> dict[str, dict]:
    """
    Displays the Mach-O source version if available.

    Args:
      binary: The Mach-O binary file being processed.
      type_of_binary: The type of the binary file, expected to be 'machofile'.

    Returns:
      A dictionary containing source version details if available.
    """
    if type_of_binary == "machofile" and binary.has_source_version:
        return {
            "Source version": {
                "Command": str(binary.source_version.command),
                "Offset": hex(binary.source_version.command_offset),
                "Size": binary.source_version.size,
                "Version": list_version_to_dotted_version(
                    binary.source_version.version
                ),
            }
        }
    else:
        logger.info("Warning: No source version found")
        return {}


def list_version_to_dotted_version(version_list: list[int]) -> Optional[str]:
    """
    Converts a version represented as a list into a dotted string representation.

    Args:
      version_list: List of version values.

    Returns:
      A formatted version string in the format '0.0.0.0....'
    """
    return ".".join(str(v) for v in version_list) if version_list else None


def interpreter(binary: lief.ELF.Binary, type_of_binary: str) -> dict[str, str]:
    """
    Displays the interpreter for ELF binaries if available.

    Args:
      binary: The ELF binary file being processed.
      type_of_binary: The type of the binary file, expected to be 'elffile'.

    Returns:
      A dictionary containing the interpreter path if available.
    """
    if type_of_binary == "elffile" and binary.has_interpreter:
        return {"Interpreter": binary.interpreter}
    else:
        logger.info("Warning: No interpreter found")
        return {}


def lief_features(subdir: str, sample: str) -> dict[str, Any]:
    """
    Analyzes a binary file with LIEF and extracts various features, saving them as a JSON file.

    Args:
        subdir: The directory where to save the features file.
        sample: The path to the binary sample to analyze.
    """
    final_result = {}

    try:
        binary = lief.parse(sample)
        type_of_binary = check_binary_format(
            binary
        )  # Updated to use the refactored function name

        # Assuming each function returns a dictionary and takes `binary` and `type_of_binary` as arguments
        functions = [
            lief_header,  # Assuming this combines common and type-specific header info
            code_signature,
            source_version,
            signature,
            interpreter,
            get_sections,
            imported_functions,
            exported_functions,
            imported_symbols,
            exported_symbols,
            resources,
            dlls,
            imports,
            load_configuration,
        ]

        # Iterating over each function and updating the final_result dictionary
        for func in functions:
            result = func(binary, type_of_binary)
            final_result.update(result)

        # Writing the results to a JSON file
        filename = "lief_features.json"
        path_to_file = os.path.join(subdir, filename)
        with open(path_to_file, "w", encoding="utf-8") as f:
            json.dump(final_result, f, indent=4)

    except Exception as e:
        logger.exception("An exception occurred during the feature extraction: %s", e)

    return final_result


def sha256(data: bytes) -> bytes:
    """
    Generates SHA-256 hash of the given data.

    Args:
        data: Data to hash.

    Returns:
        SHA-256 hash of the data.
    """
    return hashlib.sha256(data).digest()


def decode_base58(bc: str, length: int) -> bytes:
    """
    Decodes a base58-encoded string.

    Args:
        bc: Base58 encoded string.
        length: Expected length of the decoded data.

    Returns:
        Decoded data as bytes.
    """
    digits58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = 0
    for char in bc:
        n = n * 58 + digits58.index(char)
    return n.to_bytes(length, "big")


def check_bc(bc: str) -> bool:
    """
    Checks if a given Bitcoin address is valid.

    Args:
        bc: Bitcoin address.

    Returns:
        True if valid, False otherwise.
    """
    try:
        bcbytes = decode_base58(bc, 25)
        return bcbytes[-4:] == sha256(sha256(bcbytes[:-4]).digest()).digest()[:4]
    except Exception:
        return False


def ip_info(ipaddress_list: list[str]) -> list[str]:
    """
    Filters out IP addresses that belong to reserved, private, or non-routable IP ranges and returns a unique set of public IP addresses.

    Args:
        ipaddress_list: A list of IP addresses to be filtered.

    Returns:
        A set of IP addresses that are public and routable.
    """
    public_ips = set()

    for ip in ipaddress_list:
        if not ip:
            continue

        ip_part = ip.split(":", 1)[0]  # Extract IP before ":" if present
        try:
            ip_obj = ipaddress.ip_address(ip_part)
        except ValueError as e:
            print(f"Invalid IP address {ip_part}: {e}")
            continue

        # Check if the IP is reserved, private, or not globally routable
        if (
            ip_obj.is_global
            and not ip_obj.is_reserved
            and not ip_obj.is_private
            and not ip_obj.is_multicast
            and not ip_obj.is_unspecified
            and not ip_obj.is_loopback
            and not ip_obj.is_link_local
        ):
            public_ips.add(ip_part)

    return list(public_ips)


def is_valid_and_public_ip(ip: str) -> bool:
    """
    Validates an IP address and checks if it is public (globally routable).

    Args:
        ip: The IP address to validate.

    Returns:
        True if the IP address is valid and public, False otherwise.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return (
            ip_obj.is_global
            and not ip_obj.is_reserved
            and not ip_obj.is_private
            and not ip_obj.is_multicast
            and not ip_obj.is_unspecified
            and not ip_obj.is_loopback
            and not ip_obj.is_link_local
        )
    except ValueError:
        return False


def get_regex_patterns() -> dict:
    """
    Defines regular expressions for various patterns.

    Returns:
        A dictionary of pattern names to their corresponding regular expressions.
    """
    return {
        "URL": r"(http[s]?|ftp|telnet|ldap|file):\/\/([\w|\d]{2,6}\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(\:[\d]{2,6})?",
        "IPv4": r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",
        "MD5": r"[a-fA-F0-9]{32}",
        "SHA1": r"[a-fA-F0-9]{40}",
        "SHA256": r"[a-fA-F0-9]{64}",
        "WindowsFilePath": r"(?:[\w]\:|\\)(\\[a-z_\-\s0-9\.]+)+\.(txt|gif|pdf|doc|docx|xls|xlsx|msg|log|rtf|key|dat|jpg|png|exe|bat|apk|jar|js|php|htm|html|dll|lnk)",
        "LinuxFilePath": r"\/[\w]{3,10}[\/]+[\w]{1,40}[\/]+([\w|+|-|%|\.|~|_|-|\/])*[\w|+|-|%|\.|~|_|-]{1,255}",
        "Ethereum": r"^0x[a-fA-F0-9]{40}$",
        "Bitcoin": r"([13]|bc1)[A-HJ-NP-Za-km-z1-9]{25,39}",
        "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}",
        "SlackToken": r"(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
        "RSAprivatekey": r"-----BEGIN RSA PRIVATE KEY-----",
        "SSHDSAprivatekey": r"-----BEGIN DSA PRIVATE KEY-----",
        "SSHECprivatekey": r"-----BEGIN EC PRIVATE KEY-----",
        "PGPprivatekeyblock": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "GitHub": r"[gG][iI][tT][hH][uU][bB].*['|\"][0-9a-zA-Z]{35,40}['|\"]",
        "GenericAPIKey": r"[aA][pP][iI]_?[kK][eE][yY].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
        "GoogleAPIKey": r"AIza[0-9A-Za-z\\-_]{35}",
        "GoogleGCPServiceaccount": r"\"type\": \"service_account\"",
        "GoogleGmailAPIKey": r"AIza[0-9A-Za-z\\-_]{35}",
        "GoogleGmailOAuth": r"[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
        "PayPalBraintreeAccessToken": r"access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
        "TwitterAccessToken": r"[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
        "TwitterOAuth": r"[tT][wW][iI][tT][tT][eE][rR].*['|\"][0-9a-zA-Z]{35,44}['|\"]",
    }


def combine_patterns(patterns: dict[str, str]) -> re.Pattern:
    """
    Combines multiple regex patterns into a single pattern with named groups.

    Args:
        patterns: A dictionary of patterns to combine, where keys are pattern names.

    Returns:
        A compiled regex object of the combined pattern.
    """
    combined_pattern = "|".join(
        [f"(?P<{name}>{pattern})" for name, pattern in patterns.items()]
    )
    return re.compile(combined_pattern, re.MULTILINE | re.IGNORECASE)


def extract_matches_combined(
    text: str, combined_regex: re.Pattern
) -> dict[str, list[str]]:
    """
    Extracts matches for named groups in the combined regex pattern from the given text. This implementation has better
    performance than extract_with_regex_individual_patterns. However, due to the greedy approach of regular expressions, we will
    miss true positive events.

    Args:
        text: The text to search through.
        combined_regex: The compiled combined regex pattern with named groups.

    Returns:
        A dictionary where each key is a pattern name and the value is a list of unique matches for that pattern.
    """
    results = {}
    for match in combined_regex.finditer(text):
        for name, value in match.groupdict().items():
            if value:  # If there's a match for this named group
                if name not in results:
                    results[name] = [value]
                elif value not in results[name]:
                    results[name].append(value)
    return results


def extract_with_regex_individual_patterns(text: str) -> dict:
    """
    Uses regular expressions to find various patterns in the provided text, applying each pattern individually.

    Args:
        text: The text to search through.

    Returns:
        A dictionary of found patterns.
    """
    patterns = get_regex_patterns()
    results = {}

    for name, pattern in patterns.items():
        matches = set()
        for match in re.finditer(pattern, text, re.MULTILINE | re.IGNORECASE):
            # Depending on the pattern, you might want to use different groups
            matched_text = match.group(0)
            if matched_text:
                matches.add(matched_text)
        results[name] = list(matches)

    return results


def find_pattern_matches(text: str, pattern: str) -> list[str]:
    """
    Finds all matches of a single pattern in the given text.

    Args:
        text: The text to search through.
        pattern: The regex pattern to apply.

    Returns:
        A list of unique matches for the pattern.
    """
    return list(
        {
            match.group(0)
            for match in re.finditer(pattern, text, re.MULTILINE | re.IGNORECASE)
        }
    )


async def async_extract_with_regex_individual_patterns(text: str) ->dict[str, list]:
    """
    Asynchronously applies each regex pattern individually to the provided text.
    """
    patterns = (
        get_regex_patterns()
    )  # Assuming this function is defined elsewhere and returns a dict of patterns
    results = {}

    # Process each pattern asynchronously
    for name, pattern in patterns.items():
        matches = set()
        for match in re.finditer(pattern, text, re.MULTILINE | re.IGNORECASE):
            matched_text = match.group(0)
            if matched_text:
                matches.add(matched_text)
        results[name] = list(matches)

    return results


async def regex_fun(
    path_to_json: str,
    file_hash: str,
    subdir: str,
    reprocess: bool = False,
    file_name: str = "regex_results.json",
) -> None:
    """
    Asynchronously extracts various patterns like URLs, file paths, cryptographic hashes, and more from a given file.
    """
    result_filename = os.path.join(subdir, file_name)

    if os.path.exists(result_filename) and not reprocess:
        logger.info("Result file already exists: %s", result_filename)
        return

    results: dict[str, dict[str, Any]] = {file_hash: {}}

    try:
        async with aiofiles.open(path_to_json, "r", encoding="utf-8") as f:
            raw_data = await f.read()

        data: dict[str, Any] = json.loads(raw_data)
        all_strings = data.get("strings", {})
        if not all_strings:
            raise ValueError(
                f"Error: Could not find strings in the provided file '{path_to_json}'"
            )

        raw_static_strings = " ".join(
            s.get("string").strip()
            for s in all_strings.get("static_strings", [])
            if s.get("string")
        )
        details = await async_extract_with_regex_individual_patterns(raw_static_strings)
        results[file_hash] = details

        async with aiofiles.open(result_filename, "w", encoding="utf-8") as f:
            await f.write(json.dumps(results, indent=4))

    except Exception as e:
        logger.exception(
            "Exception occurred while processing file %s: %s", path_to_json, e
        )


# To run the async function, use asyncio.run() if calling from a non-async context
# Example:
# asyncio.run(regex_fun('/path/to/json', 'file_hash_example', '/sub/dir'))


# # Example usage
# macho
file_hash = "3f5fb5fd5b29a805f13611c9e8acad3ce3e319c6060d92b693378a8506714e9c"
# elf packed
# file_hash = "469aa49f4f628498111af193d9220fcc41825d94525246656e40b0560d4cd267"
# elf no packing
# file_hash = "8b6380534dcae5830e1e194f8c54466db365246cb8df998686f04818e37d84c1"
# pe binary
# file_hash = "00d1726e2ba77c4bed66a6c5c7f1a743cf7bb480deff15f034d67cf72d558c83"
# dll
# file_hash = "f4e9e73265a87139b9f090ff69d8c246ca68d858952f7eef0f0686ef24c5fbb6"
file_hash = "00bc6fcfa82a693db4d7c1c9d5f4c3d0bfbbd0806e122f1fbded034eb9a67b10"
root_dir = rf"C:\Users\ricewater\Documents\TestCorpus\{file_hash}"
floss_json_results = "flossresults_reduced_7.json"
sample_file_path = os.path.join(root_dir, file_hash)
floss_json_path = os.path.join(root_dir, floss_json_results)
floss_executable_path = "bins/floss2.2.exe"

# # Run the process_file function with asyncio's event loop
asyncio.run(process_floss_file(sample_file_path, root_dir, floss_executable_path))

# asyncio.run(regex_fun(floss_json_path, file_hash, root_dir, reprocess=True))
