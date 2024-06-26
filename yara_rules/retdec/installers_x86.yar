/*
 * YARA rules for x86 PE installer detection.
 * Copyright (c) 2017 Avast Software, licensed under the MIT license
 */

import "pe"

rule arc_sfx {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "ARC SFX"
	strings:
		$1 = { 8C C8 8C DB 8E D8 8E C0 89 ?? ?? ?? 2B C3 A3 ?? ?? 89 ?? ?? ?? BE ?? ?? B9 ?? ?? BF ?? ?? BA ?? ?? FC AC 32 C2 8A D8 }
	condition:
		$1 at pe.entry_point
}

private rule astrum_strings {
	strings:
		$1 = "Astrum Installer package #"
		$2 = "AstrumInstaller"
	condition:
		all of them
}

rule astrum_uv_01 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Astrum"
	strings:
		$fixed1 = { 55 8B EC 83 EC 0C 53 56 57 }
		$fixed2 = { E8 ?? ?? 00 00 8B CE E8 ?? ?? 00 00 8B CE E8 ?? ?? 00 00 85 C0 7D 15 33 DB 8B CE }
		$s1 = { BE 28 77 47 00 FF 75 08 8B CE }
		$s2 = { FF 15 ?? ?? ?? ?? FF 75 08 BE 18 88 47 00 8B CE }
	condition:
		all of ($fixed*) and
		1 of ($s*) and
		astrum_strings
}

rule astrum_uv_02 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Astrum"
	strings:
		$1 = { 6A 40 33 C0 59 8D BD ?? ?? ?? ?? F3 AB 66 AB AA }
	condition:
		$1 and astrum_strings
}

rule create_install {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "CreateInstall"
	strings:
		$s01 = "Gentee Launcher"
	condition:
		pe.sections[pe.number_of_sections - 2].name == ".gentee" and
		pe.overlay.size != 0 and
		pe.resources[pe.number_of_resources-1].type == pe.RESOURCE_TYPE_MANIFEST and
		pe.resources[pe.number_of_resources-2].name_string == "S\x00E\x00T\x00U\x00P\x00_\x00I\x00C\x00O\x00N\x00" and   // "SETUP_ICON"
		pe.resources[pe.number_of_resources-3].name_string == "S\x00E\x00T\x00U\x00P\x00_\x00T\x00E\x00M\x00P\x00" and   // "SETUP_TEMP"
		all of them
}

rule fly_studio {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "FlyStudio"
	condition:
		pe.overlay.size > 16 and
		uint32(pe.overlay.offset) == 0x829ab7a5 and
		uint32(pe.overlay.offset + 4) == 0x04 and
		uint32(pe.overlay.offset + pe.overlay.size - 4) == 0x829ab7a5 and
		pe.overlay.offset == filesize - uint32(pe.overlay.offset + pe.overlay.size - 8) - 0x08
}

rule gentee_installer {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "GenteeInstaller"
	strings:
		$s01 = "Gentee installer"
	condition:
		pe.overlay.size > 16 and
		uint32(0x3F0) == pe.overlay.offset and
		(uint32(0x3F4) + uint32(0x3F8)) <= pe.overlay.size and
		(uint32(pe.overlay.offset) == uint32(0x3F8)) and
		$s01 at pe.sections[2].raw_data_offset
}

rule ghost_installer {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "GhostInstaller"
	strings:
		$s01 = "GIPENDMSCF"
	condition:
		pe.number_of_sections == 3 and
		pe.sections[0].name == "UPX0" and
		pe.sections[1].name == "UPX1" and
		pe.overlay.offset != 0 and
		pe.overlay.size != 0 and
		uint32(pe.overlay.offset) == 0x4643534D and
		pe.resources[4].type == pe.RESOURCE_TYPE_DIALOG and
		pe.resources[4].name_string == "D\x00L\x00G\x00_\x00I\x00N\x00P\x00U\x00T\x00Q\x00U\x00E\x00R\x00Y\x00S\x00T\x00R\x00" and
		pe.resources[5].type == pe.RESOURCE_TYPE_DIALOG and
  		pe.resources[5].name_string == "D\x00L\x00G\x00_\x00P\x00R\x00E\x00S\x00E\x00T\x00U\x00P\x00" and
		all of them
}

rule install_creator {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "InstallCreator"
	strings:
		$s01 = { 77 77 67 54 29 48 }
	condition:
		pe.number_of_sections == 3 and
		pe.sections[0].name == "UPX0" and
		pe.sections[1].name == "UPX1" and
		pe.overlay.offset != 0 and
		pe.overlay.size != 0 and
		$s01 at pe.overlay.offset
}

rule quick_batch_compiler_2x {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Quick Batch File Compiler"
		version = "2.x"
	strings:
		$delphi_01 = "Runtime error     at 00000000"                                            // Common Delphi/Embarcadero
		$delphi_02 = "Access violation at address %p in module '%s'. %s of address %p" wide     // Found in almost all Quick Batch samples
		$s01 = "File is corrupt."
		$s02 = "Compressed file is corrupt"
		$s03 = "Quick Batch File Compiler"
		$s04 = "cmd.exe /c"
		$s05 = "a%.5u.bat"
	condition:
		pe.number_of_sections >= 8 and
		pe.sections[0].name == "CODE" and
		pe.sections[1].name == "DATA" and
		all of ($delphi_*) and
		4 of ($s*)
}

rule quick_batch_compiler_4x {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Quick Batch File Compiler"
		version = "4.x"
	strings:
		$delphi_01 = "Runtime error     at 00000000"                                            // Common Delphi/Embarcadero
		$delphi_02 = "Access violation at address %p in module '%s'. %s of address %p" wide     // Found in almost all Quick Batch samples
		$s01 = "Quick Batch File Compiler Runtime Module Version 4." wide
		$s02 = "In order to correctly identify malware while avoiding false positives, antivirus manufacturers shalldetect the presence of Quick Batch File Compiler label" wide
		$s03 = { 1A 00 00 00 53 00 63 00 72 00 69 00 70 00 74 00 43 00 72 00 79 00 70 00 74 00 6F 00 72 00 00 00 }  // Delphi "ScriptCryptor"
	condition:
		pe.number_of_sections >= 8 and
		all of ($delphi_*) and
		2 of ($s*)
}

rule quick_batch_compiler {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Quick Batch File Compiler"
		version = "2.x - 4.x"
	strings:
		$qbatch_01 = "Runtime error     at 00000000"                                            // Common Delphi/Embarcadero
		$qbatch_02 = "Access violation at address %p in module '%s'. %s of address %p" wide     // Found in almost all Quick Batch samples
		$qbatch_03 = "http://www.abyssmedia.com"                                                // Found in some samples
		$code_01 = { c7 05 ?? ?? ?? 00 63 51 e1 b7 bb 2b 00 00 00 b8 ?? ?? ?? 00 8b 10 81 c2 b9 79 37 9e 89 }
		$code_02 = { 6a 00 6a 00 6a 20 6a 00 6a 00 6a 00 8b 45 ?? e8 ?? ?? ?? ?? 50 6a 00 e8 }
		$code_03 = { 6a 00 6a 00 6a 20 6a 00 6a 00 6a 00 a1 ?? ?? ?? 00 e8 ?? ?? ?? ?? 50 6a 00 e8 }
		$code_04 = { 6a 00 6a 00 6a 20 6a ff 68 ?? ?? ?? 00 68 ?? ?? ?? 00 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 6a 00 e8 }
		$s10 = "Quick Batch File Compiler" ascii wide
		$s20 = "RC_SCRIPT" wide
		$s21 = "MYFILES" wide
		$s22 = "SCRIPT" wide
	condition:
		pe.number_of_sections >= 8 and
		(pe.sections[0].name == "CODE" or pe.sections[0].name == ".text") and
		(pe.sections[1].name == "DATA" or pe.sections[2].name == ".data") and
		2 of ($qbatch_*) and
		((2 of ($code_*)) or (3 of ($s*))) and
		any of ($s*)
}

rule kgb_sfx {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "KGB SFX"
	strings:
		$1 = { 60 BE 00 A0 46 00 8D BE 00 70 F9 FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 }
	condition:
		$1 at pe.entry_point
}

rule gsfx {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "GSFX"
	strings:
		$1 = { 47 53 46 58 }
	condition:
		$1 at pe.entry_point
}

rule cipherwall_sfx_15_console {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "CipherWall SFX"
		version = "1.5"
		description = "console version"
	strings:
		$1 = { 90 61 BE 00 10 42 00 8D BE 00 00 FE FF C7 87 C0 20 02 00 0B 6E 5B 9B 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 08 8A 06 46 83 F0 FF 74 74 89 C5 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 75 20 41 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 83 C1 02 81 FD }
	condition:
		$1 at pe.entry_point
}

rule cipherwall_sfx_15_gui {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "CipherWall SFX"
		version = "1.5"
		description = "GUI version"
	strings:
		$1 = { 90 61 BE 00 10 42 00 8D BE 00 00 FE FF C7 87 C0 20 02 00 F9 89 C7 6A 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 08 8A 06 46 83 F0 FF 74 74 89 C5 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 75 20 41 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 83 C1 02 81 FD }
	condition:
		$1 at pe.entry_point
}

rule gp_install_50332 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "GP-Install"
		version = "5.0.3.32"
	strings:
		$1 = { 55 8B EC 33 C9 51 51 51 51 51 51 51 53 56 57 B8 C4 1C 41 00 E8 6B 3E FF FF 33 C0 55 68 76 20 41 00 64 FF 30 64 89 20 BA A0 47 41 00 33 C0 E8 31 0A FF FF 33 D2 A1 A0 }
	condition:
		$1 at pe.entry_point
}

rule createinstall {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "CreateInstall"
	strings:
		$1 = { 55 8B EC 81 EC 20 02 00 00 53 56 57 6A 00 FF 15 18 61 40 00 68 00 70 40 00 89 45 08 FF 15 14 61 40 00 85 C0 74 27 6A 00 A1 00 20 40 00 50 FF 15 3C 61 40 00 8B F0 6A 06 56 FF 15 38 61 40 00 6A 03 56 FF 15 38 61 40 00 E9 36 03 00 00 68 02 7F }
	condition:
		$1 at pe.entry_point
}

rule createinstall_2000_35 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "CreateInstall"
		version = "2003.3.5"
	strings:
		$1 = { 81 EC 0C 04 00 00 53 56 57 55 68 60 50 40 00 6A 01 6A 00 FF 15 D8 80 40 00 8B F0 FF 15 D4 80 40 00 3D B7 00 00 00 75 0F 56 FF 15 B8 80 40 00 6A 02 FF 15 A4 80 40 00 33 DB E8 F2 FE FF FF 68 02 7F 00 00 89 1D 94 74 40 00 53 89 1D 98 74 40 00 }
	condition:
		$1 at pe.entry_point
}

rule exemplar_installer {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Exemplar Installer"
	strings:
		$1 = { 55 8B EC 83 EC ?? 53 56 57 FF 15 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 8B F0 85 F6 75 ?? 6A ?? FF D3 8A 06 8B 3D ?? ?? ?? ?? 3C ?? 75 ?? 56 FF D7 }
	condition:
		$1 at pe.entry_point
}

rule pyinstaller_27
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "PyInstaller"
		version = "2.7"
		strength = "high"
	strings:
		$s00 = "Cannot GetProcAddress for PySys_SetObject"
		$s01 = "Error coping %s"
		$s02 = "Error loading Python DLL: %s (error code %d)"
		$s03 = "PYTHONHOME"
	condition:
		pe.number_of_resources > 0 and
		@s00 < pe.sections[2].raw_data_offset and
		all of them
}

rule pyinstaller_3x
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "PyInstaller"
		version = "3.x"
		strength = "high"
	strings:
		$s00 = "Failed to get address for PySys_SetObject"
		$s01 = "Error copying %s"
		$s02 = "Error loading Python DLL '%s'"
		$s03 = "pyi-windows-manifest-filename"
	condition:
		pe.number_of_resources > 0 and
		@s00 < pe.sections[2].raw_data_offset and
		all of them
}

rule installanywhere_61 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "InstallAnywhere"
		version = "6.1"
	strings:
		$1 = { 60 BE 00 A0 42 00 8D BE 00 70 FD FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 }
	condition:
		$1 at pe.entry_point
}

rule installshield_uv_01 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "InstallShield"
		start = 96
	strings:
		$1 = { 45 BC 50 FF 15 ?? ?? 41 00 F6 45 E8 01 5F 74 06 0F B7 45 EC EB 03 6A 0A 58 50 56 6A 00 6A 00 FF }
	condition:
		$1 at pe.entry_point + 96
}

rule installshield_uv_02 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "InstallShield"
	strings:
		$1 = { 55 8B EC 81 EC 14 ?? 00 00 53 56 57 6A 00 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 74 29 }
	condition:
		$1 at pe.entry_point
}

rule installshield_uv_3 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "InstallShield"
	strings:
		$1 = { 55 8B EC 83 EC 44 56 FF 15 ?? ?? 41 00 8B F0 85 F6 75 08 6A FF FF 15 ?? ?? 41 00 8A 06 57 8B 3D ?? ?? 41 00 3C 22 75 1B 56 FF D7 8B F0 8A 06 3C 22 74 04 84 C0 75 F1 80 3E 22 75 15 56 FF D7 8B }
	condition:
		$1 at pe.entry_point
}

rule installshield_uv_05 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "InstallShield"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 EC 44 56 FF 15 ?? ?1 41 00 8B F0 85 F6 75 08 6A FF FF 15 ?? ?1 41 00 8A 06 57 8B 3D ?? ?2 41 00 3C 22 75 1B 56 FF D7 8B F0 8A 06 3C 22 74 04 84 C0 75 F1 80 3E 22 75 15 56 FF D7 8B F0 EB 0E 3C 20 7E 0A 56 FF D7 8B F0 80 3E 20 7F F6 8A 06 84 C0 74 04 3C 20 7E E1 83 65 E8 00 8D 45 BC 50 FF }
	condition:
		$1 at pe.entry_point
}

rule instyler_uv_01 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Instyler"
	strings:
		$1 = { 49 53 01 1A 00 }
	condition:
		$1 at pe.entry_point
}

rule instyler_uv_02 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Instyler"
	strings:
		$1 = { 69 79 45 78 69 74 49 44 }
	condition:
		$1 at pe.entry_point
}

rule sentinel_110_ultrapro_dongle {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Sentinel"
		version = "1.1.0 UltraPro Dongle"
	strings:
		$1 = { A1 ?? ?? ?? ?? 85 C0 0F 85 59 06 00 00 55 56 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? 25 FE ?? ?? ?? 0D 01 ?? ?? ?? A3 ?? ?? ?? ?? 33 C0 50 C7 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 BD 0F 00 00 83 C4 04 83 F8 64 7C E7 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF D6 68 ?? ?? ?? ?? FF D6 68 ?? ?? ?? ?? FF D6 68 ?? ?? ?? ?? FF D6 68 ?? ?? ?? ?? FF D6 A1 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 66 8B 4D 00 83 C5 08 ?? ?? ?? ?? ?? ?? ?? 66 8B 75 FA ?? ?? ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? ?? 8B 55 FC 81 E1 FF FF 00 00 81 F9 }
	condition:
		$1 at pe.entry_point
}

rule sentinel_54200_superpro_dongle {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Sentinel"
		version = "5.42.0.0 SuperPro Dongle"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B9 10 FF 00 00 BB 00 00 00 00 E8 ?? ?? ?? ?? 68 B9 20 FF 00 00 E8 ?? ?? ?? ?? 68 B9 30 FF 00 00 E8 ?? ?? ?? ?? 68 E8 ?? ?? ?? ?? 68 27 F0 10 7F E8 ?? ?? ?? ?? 68 BB 02 00 00 00 E8 ?? ?? ?? ?? 68 07 D4 30 7F E8 ?? ?? ?? ?? 68 BB 01 00 00 00 E8 ?? ?? ?? ?? 68 50 1E DF 80 E8 ?? ?? ?? ?? 68 B9 10 12 00 00 BB 00 00 00 00 E8 ?? ?? ?? ?? 68 B9 20 12 00 00 E8 ?? ?? ?? ?? 68 E8 ?? ?? ?? ?? 68 07 2A A3 00 E8 ?? ?? ?? ?? 68 BB 01 00 00 00 E8 ?? ?? ?? ?? 68 88 B5 5B FF E8 ?? ?? ?? ?? 68 B9 30 12 00 00 BB 00 00 00 00 E8 ?? ?? ?? ?? 68 }
	condition:
		$1 at pe.entry_point
}

rule sentinel_640_superpro_automatic_protection {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Sentinel"
		version = "6.4.0 SuperPro Automatic Protection"
	strings:
		$1 = { 68 ?? ?? ?? ?? 6A 01 6A 00 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 33 C9 3D B7 00 00 00 A1 ?? ?? ?? ?? 0F 94 C1 85 C0 89 0D ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 55 56 C7 05 ?? ?? ?? ?? 01 00 00 00 FF 15 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? 25 FE FF DF 3F 0D 01 00 20 00 A3 ?? ?? ?? ?? 33 C0 50 C7 04 85 ?? ?? ?? ?? 00 00 00 00 E8 ?? ?? ?? ?? 83 C4 04 83 F8 64 7C ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF D6 68 ?? ?? ?? ?? FF D6 68 }
	condition:
		$1 at pe.entry_point
}

rule sentinel_641_superpro_automatic_protection {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Sentinel"
		version = "6.4.1 SuperPro Automatic Protection"
	strings:
		$1 = { A1 ?? ?? ?? ?? 55 8B ?? ?? ?? 85 C0 74 ?? 85 ED 75 ?? A1 ?? ?? ?? ?? 50 55 FF 15 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 55 51 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 8B 15 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 6A 00 6A 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 01 00 00 00 5D C2 0C 00 68 ?? ?? ?? ?? 6A 01 6A 00 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 33 C9 3D B7 00 00 00 A1 ?? ?? ?? ?? 0F 94 C1 85 C0 89 0D ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 56 C7 05 ?? ?? ?? ?? 01 00 00 00 FF 15 ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? FF 15 }
	condition:
		$1 at pe.entry_point
}

rule setup_factory_install_package {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Setup Factory"
		version = "Installer Package"
	strings:
		$s1 = { E0 E1 E2 E3 E4 E5 E6 E7 }
		$s2 = { E0 E0 E1 E1 E2 E2 E3 E3 E4 E4 E5 E5 E6 E6 E7 E7 }
	condition:
		pe.overlay.size > 0x10 and
		($s1 at pe.overlay.offset or $s2 at pe.overlay.offset)
}

rule setup_factory_install_app {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Setup Factory"
		version = "Setup Launcher"
	strings:
		$s1 = "PKWARE Data Compression Library for Win32"
		$s3 = "irsetup.dat"
		$s4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SharedDLLs"
		$s5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"
	condition:
		(
			pe.version_info["CompanyName"] == "Indigo Rose Corporation" or
			pe.version_info["LegalTrademarks"] == "Setup Factory is a trademark of Indigo Rose Corporation"
		)
		and
		(
			pe.version_info["FileDescription"] contains "Setup Factory 4." or
			pe.version_info["ProductName"] contains "Setup Factory 5." or
			pe.version_info["ProductName"] contains "Setup Factory 6." or
			pe.version_info["ProductName"] contains "Setup Factory 8."
		)
		and
		(
			all of them
		)
}

rule setup_factory_install_app_upx {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Setup Factory"
		version = "Setup Launcher 7.0"
	condition:
		pe.number_of_sections == 3 and
		pe.sections[0].name == "UPX0" and
		pe.version_info["Comments"] == "Created with Setup Factory 7.0" and
		pe.version_info["ProductName"] == "Setup Factory 7.0 Runtime"
}

rule setup2go {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Setup2Go"
	strings:
		$1 = { 5B 53 45 54 55 50 5F 49 4E 46 4F 5D 0D 0A 56 65 72 }
	condition:
		$1 at pe.entry_point
}

rule smart_install_maker_v4 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Smart Install Maker"
		version = "4.x"
	strings:
		$s01 = "Smart Install Maker" nocase
		$s02 = "SMART INSTALL MAKER" nocase
		$s03 = "c:\\delphi7\\Lib\\km\\KOL.pas"
		$s04 = "TLZMADecompressor"
		$s05 = "Can not create DIB section, error:"
	condition:
		pe.number_of_sections == 8 and
		pe.sections[0].name == "CODE" and           // Delphi
		pe.sections[1].name == "DATA" and
		pe.overlay.size != 0 and
		all of them
}

rule smart_install_maker_v5 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Smart Install Maker"
		version = "5.x"
	strings:
		$s01 = "Smart Install Maker" nocase
		$s02 = "SMART INSTALL MAKER" nocase
	condition:
		pe.number_of_sections == 8 and
		pe.sections[0].name == "CODE" and           // Delphi
		pe.sections[1].name == "DATA" and
		pe.overlay.size != 0 and
		$s01 at pe.overlay.offset and
		all of them
}

rule thinstall_uv {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Thinstall"
		start = 16
	strings:
		$1 = { FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C }
	condition:
		$1 at pe.entry_point + 16
}

rule thinstall_19_2460 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Thinstall"
		version = "1.9 - 2.460"
	strings:
		$1 = { 55 8B EC 51 53 56 57 6A 00 6A 00 FF 15 ?? ?? ?? ?? 50 E8 87 FC FF FF 59 59 A1 ?? ?? ?? ?? 8B 40 10 03 05 ?? ?? ?? ?? 89 45 FC 8B 45 FC FF E0 5F 5E 5B C9 C3 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule thinstall_2313_2403 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Thinstall"
		version = "2.312 - 2.403"
	strings:
		$1 = { 6A 00 FF 15 ?? ?? ?? ?? E8 D4 F8 FF FF E9 E9 AD FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 }
	condition:
		$1 at pe.entry_point
}

rule thinstall_24_25 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Thinstall"
		version = "2.4 - 2.5"
	strings:
		$1 = { 55 8B EC B8 ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 E8 00 00 00 00 58 2D ?? ?? ?? ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? BD ?? ?? ?? ?? 03 E8 }
	condition:
		$1 at pe.entry_point
}

rule thinstall_2547_2628 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Thinstall"
		version = "2.547 - 2.628"
	strings:
		$1 = { E8 00 00 00 00 58 BB ?? ?? 00 00 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? 00 00 68 ?? ?? 00 00 E8 ?? ?? FF FF E9 ?? FF FF FF }
	condition:
		for any of them : ( $ in (pe.entry_point .. pe.entry_point + 12) )
}

rule thinstall_27xx {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Thinstall"
		version = "2.7xx"
	strings:
		$1 = { 9C 60 E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 }
	condition:
		$1 at pe.entry_point
}

rule thinstall_3035_3043 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Thinstall"
		version = "3.035 - 3.043"
	strings:
		$1 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 37 1F 00 00 2B C3 50 68 ?? ?? ?? ?? 68 00 28 00 00 68 04 01 00 00 E8 BA FE FF FF E9 90 FF FF FF CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 }
	condition:
		$1 at pe.entry_point
}

rule thinstall_20x_embedded {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Thinstall"
		version = "2.0x embedded"
	strings:
		$1 = { B8 EF BE AD DE 50 6A 00 FF 15 ?? ?? ?? ?? E9 AD FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 14 80 00 00 00 C2 04 00 55 8B EC 53 56 57 33 C0 33 FF 39 45 0C 8B F1 76 0C 8B 4D 08 03 3C 81 40 3B 45 0C 72 F4 8B CE E8 43 00 00 00 8B 46 14 33 D2 F7 F7 8B 5E 10 33 D2 8B F8 8B C3 F7 F7 89 7E 18 89 45 0C 33 C0 33 C9 8B 55 08 03 0C 82 40 39 4D 0C 73 F4 48 8B 14 82 2B CA 0F AF CF 2B D9 0F AF FA 89 7E 14 89 5E 10 5F 5E 5B 5D C2 08 00 }
	condition:
		$1 at pe.entry_point
}

rule thinstall_22xx_2308_embedded {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Thinstall"
		version = "2.2xx - 2.308 embedded"
	strings:
		$1 = { B8 EF BE AD DE 50 6A 00 FF 15 ?? ?? ?? ?? E9 B9 FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 14 80 00 00 00 C2 04 00 55 8B EC 53 56 57 33 C0 33 FF 39 45 0C 8B F1 76 0C 8B 4D 08 03 3C 81 40 3B 45 0C 72 F4 8B CE E8 43 00 00 00 8B 46 14 33 D2 F7 F7 8B 5E 10 33 D2 8B F8 8B C3 F7 F7 89 7E 18 89 45 0C 33 C0 33 C9 8B 55 08 03 0C 82 40 39 4D 0C 73 F4 48 8B 14 82 2B CA 0F AF CF 2B D9 0F AF FA 89 7E 14 89 5E 10 5F 5E 5B 5D C2 08 00 }
	condition:
		$1 at pe.entry_point
}

rule thinstall_2545_embedded {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Thinstall"
		version = "2.545 embedded"
	strings:
		$1 = { E8 F2 FF FF FF 50 68 ?? ?? ?? ?? 68 40 1B 00 00 E8 42 FF FF FF E9 9D FF FF FF 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule thinstall_3049_3080_vs {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Thinstall"
		version = "3.049 - 3.080 virtualization suite"
	strings:
		$1 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 37 1F 00 00 2B C3 50 68 ?? ?? ?? ?? 68 00 2C 00 00 68 04 01 00 00 E8 BA FE FF FF E9 90 FF FF FF CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 }
	condition:
		$1 at pe.entry_point
}

rule thinstall_30xx_vs {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Thinstall"
		version = "3.0xx virtualization suite"
	strings:
		$1 = { 9C 60 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 BA FE FF FF E9 ?? ?? ?? ?? CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA }
	condition:
		$1 at pe.entry_point
}

rule thinstall_3100_3332_vs {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Thinstall"
		version = "3.100 - 3.332 virtualization suite"
	strings:
		$1 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 2C FF FF FF E9 90 FF FF FF CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 }
	condition:
		$1 at pe.entry_point
}

rule thinstall_3348_3350_vs {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Thinstall"
		version = "3.348 - 3.350 virtualization suite"
	strings:
		$1 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 59 19 00 00 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 AC 00 00 00 E8 2C FF FF FF E9 ?? FF FF FF CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB A2 B9 01 00 00 00 E8 D0 00 00 00 83 C0 07 89 45 F8 C6 45 F7 00 83 F8 08 74 89 E8 B1 00 00 00 88 45 F7 E9 7C FF FF FF B9 07 00 00 00 E8 AA 00 00 00 50 33 C9 B1 02 E8 A0 00 00 00 8B C8 41 41 58 0B C0 74 04 8B D8 EB 5E 83 F9 02 74 6A 41 E8 88 00 00 00 89 45 FC E9 48 FF FF FF E8 87 00 00 00 49 E2 09 8B C3 E8 7D 00 00 00 EB 3A 49 8B C1 55 8B 4D FC 8B E8 33 C0 D3 E5 E8 5D 00 00 00 0B C5 5D 8B D8 E8 5F 00 00 00 3D 00 00 01 00 73 14 3D FF 37 00 00 73 0E 3D 7F 02 00 00 73 08 83 F8 7F 77 04 41 41 41 41 56 8B F7 2B F0 F3 A4 5E E9 F0 FE FF FF 33 C0 EB 05 8B C7 2B 45 0C 5E 5F 5B C9 C2 08 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 C3 B9 08 00 00 00 E8 01 00 00 00 C3 33 C0 E8 E1 FF FF FF 13 C0 E2 F7 C3 33 C9 41 E8 D4 FF FF FF 13 C9 E8 CD FF FF FF 72 F2 C3 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule viseman {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Viseman Installer"
	condition:
		pe.overlay.offset != 0 and
		pe.overlay.size > 4 and
		uint32(pe.overlay.offset) == 0x56495345     // Reversed "VISE"
}

rule wise_installer_uv_01 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Wise Installer"
	strings:
		$1 = { 55 8B EC 81 EC ?? ?? 00 00 53 56 57 6A ?? ?? ?? ?? ?? ?? ?? FF 15 ?? ?? 40 00 }
	condition:
		$1 at pe.entry_point
}

rule wise_installer_uv_02 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Wise Installer"
	strings:
		$1 = { 81 EC 20 0F 00 00 56 57 6A 04 FF 15 0C 61 40 00 33 FF 89 7C 24 40 89 7C 24 24 89 7C 24 20 89 7C 24 28 89 7C 24 1C FF 15 A4 60 40 00 8A 08 80 F9 22 89 44 24 30 75 2A EB 05 80 F9 22 74 10 40 8A }
	condition:
		$1 at pe.entry_point
}

rule wise_installer_uv_03 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Wise Installer"
	strings:
		$1 = { 55 8B EC 81 EC BC 04 00 00 53 56 57 6A 04 FF 15 64 30 40 00 FF 15 50 30 40 00 8B F0 89 75 F4 8A 06 3C 22 0F 85 98 00 00 00 8A 46 01 46 89 75 F4 33 DB 3A C3 74 0D 3C 22 74 09 8A 46 01 46 89 75 }
	condition:
		$1 at pe.entry_point
}

rule wise_installer_uv_04 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Wise Installer"
	strings:
		$1 = { 55 8B EC 81 EC 78 05 00 00 53 56 BE 04 01 00 00 57 8D 85 94 FD FF FF 56 33 DB 50 53 FF 15 3? 20 40 00 8D 85 94 FD FF FF 56 50 8D 85 94 FD FF FF 50 FF 15 3? 20 40 00 8B 3D ?? 20 40 00 53 53 6A }
		$2 = { 55 8b ec 81 ec 74 05 00 00 53 8d 85 98 fd ff ff 56 33 db 57 be 04 01 00 00 56 50 53 ff 15 b4 40 40 00 56 8d 85 98 fd ff ff 50 50 ff 15 8c 40 40 00 53 8d 8d 98 fd ff ff 53 6a 03 53 6a 01 68 00 }
		$3 = { 55 8b ec 81 ec 7c 05 00 00 53 56 57 be 04 01 00 00 56 8d 85 90 fd ff ff 33 db 50 53 89 5d f4 ff 15 38 20 40 00 56 8d 85 90 fd ff ff 50 50 ff 15 34 20 40 00 8b 3d 30 20 40 00 53 53 6a 03 53 6a }
	condition:
		$1 at pe.entry_point or
		$2 at pe.entry_point or
		$3 at pe.entry_point
}

rule wise_installer_uv_05 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Wise Installer"
	strings:
		$s01 = "WISE_SETUP_EXE_PATH=\"%s\""
		$s02 = "Wise Installation"
		$s03 = "WiseInitLangAlwaysPrompt"
		$s04 = "Initializing Wise Installation Wizard..."
	condition:
		pe.number_of_sections == 5 and
		pe.sections[3].name == ".WISE" and
		all of them
}

rule wise_installer_uv_06 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Wise Installer"
	strings:
		$h01 = { 64 a1 00 00 00 00 55 8b ec 6a ff 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 89 25 00 00 00 00 83 ec }
		$h02 = { 55 8b ec 6a ff 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec }
		$s01 = "GLBSInstall"
		$s02 = "System DLLs corrupt or missing."
		$s03 = "Could not locate installer DLL."
		$s04 = "WiseMain"
		$s05 = "Corrupt installation detected."
		$s06 = "The installation file may be corrupt."
	condition:
		pe.number_of_sections >= 4 and
		($h01 at pe.entry_point or $h02 at pe.entry_point) and
		4 of ($s*)
}

rule wise_installer_110 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Wise Installer"
		version = "1.10"
	strings:
		$1 = { 55 8B EC 81 EC 40 0F 00 00 53 56 57 6A 04 FF 15 F4 30 40 00 FF 15 74 30 40 00 8A 08 89 45 E8 80 F9 22 75 48 8A 48 01 40 89 45 E8 33 F6 84 C9 74 0E 80 F9 22 74 09 8A 48 01 40 89 45 E8 EB EE 80 38 22 75 04 40 89 45 E8 80 38 20 75 09 40 80 38 20 74 FA 89 45 E8 8A 08 80 F9 2F 74 2B 84 C9 74 1F 80 F9 3D 74 1A 8A 48 01 40 EB F1 33 F6 84 C9 74 D6 80 F9 20 74 }
	condition:
		$1 at pe.entry_point
}

rule nsis_1xx {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Nullsoft Install System"
		version = "1.xx"
	strings:
		$1 = { 83 EC 0C 53 56 57 FF 15 20 71 40 00 05 E8 03 00 00 BE 60 FD 41 00 89 44 24 10 B3 20 FF 15 28 70 40 00 68 00 04 00 00 FF 15 28 71 40 00 50 56 FF 15 08 71 40 00 80 3D 60 FD 41 00 22 75 08 80 C3 02 BE 61 FD 41 00 8A 06 8B 3D F0 71 40 00 84 C0 74 0F 3A C3 74 0B 56 FF D7 8B F0 8A 06 84 C0 75 F1 80 3E 00 74 05 56 FF D7 8B F0 89 74 24 14 80 3E 20 75 07 56 FF D7 8B F0 EB F4 80 3E 2F 75 }
	condition:
		$1 at pe.entry_point
}

rule nsis_1xx_pimp {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Nullsoft Install System"
		version = "1.xx PiMP"
	strings:
		$1 = { 83 EC 5C 53 55 56 57 FF 15 ?? ?? ?? 00 }
	condition:
		$1 at pe.entry_point
}

rule nsis_overlay_data {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Nullsoft Install System"
	strings:
		$s01 = { EF BE AD DE 6E 73 69 73 69 6E 73 74 61 6C 6C 00 }
		$s02 = { ED BE AD DE 4E 75 6C 6C 53 6F 66 74 49 6E 73 74 }
		$s03 = { 0? 00 00 00 EF BE AD DE 4E 75 6C 6C (53|73) 6F 66 74 49 6E 73 74 }
	condition:
		pe.number_of_sections > 3 and
		pe.overlay.size != 0 and
		(
			@s01 >= pe.overlay.offset or
			@s02 >= pe.overlay.offset or
			@s03 >= pe.overlay.offset
		)
}

rule nsis_13x_pimp {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Nullsoft Install System"
		version = "1.3x PIMP"
	strings:
		$1 = { 55 8B EC 81 EC ?? ?? 00 00 56 57 6A ?? BE ?? ?? ?? ?? 59 8D BD }
	condition:
		$1 at pe.entry_point
}

rule nsis_20rc2 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Nullsoft Install System"
		version = "2.0rc2"
	strings:
		$1 = { 83 EC 10 53 55 56 57 C7 44 24 14 70 92 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00 55 FF 15 84 72 40 00 BE 00 54 43 00 BF 00 04 00 00 56 57 A3 A8 EC 42 00 FF 15 C4 70 40 00 E8 8D FF FF FF 8B 1D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 5C 71 40 00 }
	condition:
		$1 at pe.entry_point
}

rule nsis_20 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Nullsoft Install System"
		version = "2.0"
	strings:
		$1 = { 83 EC 0C 53 55 56 57 C7 44 24 10 70 92 40 00 33 DB C6 44 24 14 20 FF 15 2C 70 40 00 53 FF 15 84 72 40 00 BE 00 54 43 00 BF 00 04 00 00 56 57 A3 A8 EC 42 00 FF 15 C4 70 40 00 E8 8D FF FF FF 8B 2D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 5C 71 40 00 }
	condition:
		$1 at pe.entry_point
}

rule nsis_20b2_20b3 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Nullsoft Install System"
		version = "2.0b2, 2.0b3"
	strings:
		$1 = { 83 EC 0C 53 55 56 57 FF 15 ?? 70 40 00 8B 35 ?? 92 40 00 05 E8 03 00 00 89 44 24 14 B3 20 FF 15 2C 70 40 00 BF 00 04 00 00 68 ?? ?? ?? 00 57 FF 15 ?? ?? 40 00 57 FF 15 }
	condition:
		$1 at pe.entry_point
}

rule nsis_20b4_01 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Nullsoft Install System"
		version = "2.0b4"
	strings:
		$1 = { 83 EC 10 53 55 56 57 C7 44 24 14 F0 91 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00 55 FF 15 88 72 40 00 BE 00 D4 42 00 BF 00 04 00 00 56 57 A3 60 6F 42 00 FF 15 C4 70 40 00 E8 9F FF FF FF 8B 1D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 60 71 40 00 }
	condition:
		$1 at pe.entry_point
}

rule nsis_20b4_02 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Nullsoft Install System"
		version = "2.0b4"
	strings:
		$1 = { 83 EC 14 83 64 24 04 00 53 55 56 57 C6 44 24 13 20 FF 15 30 70 40 00 BE 00 20 7A 00 BD 00 04 00 00 56 55 FF 15 C4 70 40 00 56 E8 7D 2B 00 00 8B 1D 8C 70 40 00 6A 00 56 FF D3 BF 80 92 79 00 56 57 E8 15 26 00 00 85 C0 75 38 68 F8 91 40 00 55 56 FF 15 60 71 40 00 03 C6 50 E8 78 29 00 00 56 E8 47 2B 00 00 6A 00 56 FF D3 56 57 E8 EA 25 00 00 85 C0 75 0D C7 44 24 14 58 91 40 00 E9 72 02 00 00 57 FF 15 24 71 40 00 68 EC 91 40 00 57 E8 43 }
	condition:
		$1 at pe.entry_point
}

rule nsis_202_208
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Nullsoft Install System"
		version = "2.02 - 2.08"
		source = "Made by Retdec Team"
	strings:
		$1 = { 83 EC 20 53 55 56 33 DB 57 89 5C 24 18 C7 44 24 10 ?? ?? 40 00 C6 44 24 14 20 FF 15 ?? ?0 40 00 53 FF 15 ?? ?2 40 00 68 ?? ?? 40 00 68 ?0 ?? ?? 00 A3 ?0 ?? ?? 00 E8 ?? 2? 00 00 BE 00 ?? ?? 00 ?? ?? 0? 0? 00 ?? 57 FF 15 ?? ?? 40 00 E8 ?? FF FF FF 8? ?? ?? ?? ?? ?0 ?? ?0 75 21 68 FB 0? 00 00 56 FF 15 }
	condition:
		$1 at pe.entry_point
}

rule nsis_209_210
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Nullsoft Install System"
		version = "2.09 - 2.10"
		source = "Made by Retdec Team"
	strings:
		$1 = { 83 EC 20 53 55 56 33 F6 57 89 74 24 18 B? ?? ?? 40 00 89 74 24 14 C6 44 24 10 20 FF 15 30 ?0 40 00 56 FF 15 8? ?2 40 00 68 ?? ?? 40 00 68 ?0 ?? 4? 00 A3 ?0 ?? 4? 00 E8 ?? 2? 00 00 B? 00 ?? 4? 00 BF 00 ?? 00 00 5? 57 FF 15 ?? ?? 40 00 E8 79 FF FF FF 85 C0 75 24 68 FB ?? 00 00 5? FF 15 ?? ?? 40 00 68 }
	condition:
		$1 at pe.entry_point
}

rule nsis_211_212
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Nullsoft Install System"
		version = "2.11 - 2.12"
		source = "Made by Retdec Team"
	strings:
		$1 = { 81 EC 80 01 00 00 53 55 56 33 F6 57 89 74 24 18 B? ?? ?? 40 00 89 74 24 10 C6 44 24 14 20 FF 15 30 ?0 40 00 56 FF 15 ?? ?2 40 00 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 56 68 ?? ?? 4? 00 FF 15 ?? ?1 40 00 68 ?? ?? 40 00 68 ?0 ?? 4? 00 E8 ?? 2? 00 00 B? 00 ?? 4? 00 ?? ?? ?? 0? 00 ?? 57 FF 15 }
	condition:
		$1 at pe.entry_point
}

rule nsis_213_223
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Nullsoft Install System"
		version = "2.13 - 2.23"
		source = "Made by Retdec Team"
	strings:
		$1 = { 81 EC 7C 01 00 00 53 55 56 33 F6 57 89 74 24 18 B? ?0 ?? 40 00 C6 44 24 10 20 FF 15 30 ?0 40 00 56 FF 15 7? ?2 40 00 A3 ?0 ?? 4? 00 56 8D 44 24 30 68 60 01 00 00 50 56 68 ?? ?? 4? 00 FF 15 58 ?1 40 00 68 ?? ?? 40 00 68 ?0 ?? 4? 00 E8 ?? 2? 00 00 B? 00 ?? 4? 00 5? 68 00 ?? 00 00 FF 15 B? ?0 40 00 E8 }
	condition:
		$1 at pe.entry_point
}

rule nsis_224
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Nullsoft Install System"
		version = "2.24"
		source = "Made by Retdec Team"
	strings:
		$1 = { 81 EC 80 01 00 00 53 55 56 33 DB 57 89 5C 24 18 C7 44 24 14 ?0 9? 40 00 33 F6 C6 44 24 10 20 FF 15 30 70 40 00 53 FF 15 74 72 40 00 A3 ?0 ?? 42 00 53 8D 44 24 34 68 60 01 00 00 50 53 68 ?? ?? 4? 00 FF 15 5C 71 40 00 68 ?? 92 40 00 68 ?0 ?? 42 00 E8 ?? 28 00 00 FF 15 B? 70 40 00 BF 00 ?0 4? 00 50 57 }
	condition:
		$1 at pe.entry_point
}

rule nsis_225
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Nullsoft Install System"
		version = "2.25"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 81 EC 80 01 00 00 53 56 33 DB 57 89 5D F4 C7 45 F8 ?? ?? 40 00 89 5D FC C6 45 EC 20 FF 15 30 70 40 00 53 FF 15 7? 72 40 00 ?3 ?? ?? ?? 00 ?? ?? ?? ?0 ?? ?? ?? ?? ?0 ?? ?? ?? 50 53 68 ?? ?? ?? 00 FF 15 5? 71 40 00 68 ?? ?? 40 00 68 ?0 ?? ?? 00 E8 ?? 2? 00 00 FF 15 B? 70 40 00 ?? ?? ?0 }
	condition:
		$1 at pe.entry_point
}

rule nsis_226_228
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Nullsoft Install System"
		version = "2.26 - 2.28"
		source = "Made by Retdec Team"
	strings:
		$1 = { 81 EC 80 01 00 00 53 55 56 33 DB 57 89 5C 24 18 C7 44 24 10 ?? 91 40 00 33 F6 C6 44 24 14 20 FF 15 30 70 40 00 53 FF 15 78 72 40 00 A3 ?4 ?? ?? 00 53 8D 44 24 34 68 60 01 00 00 50 53 68 ?? ?? ?? 00 FF 15 54 71 40 00 68 ?? 9? 40 00 68 ?0 ?? ?? 00 E8 ?? 27 00 00 FF 15 B? 70 40 00 BF 00 ?0 ?? 00 50 57 }
	condition:
		$1 at pe.entry_point
}

rule nsis_229
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Nullsoft Install System"
		version = "2.29"
		source = "Made by Retdec Team"
	strings:
		$1 = { 81 EC 80 01 00 00 53 55 56 33 DB 57 89 5C 24 18 C7 44 24 10 ?? 91 40 00 33 F6 C6 44 24 14 20 FF 15 30 70 40 00 68 01 80 00 00 FF 15 B? 70 40 00 53 FF 15 78 72 40 00 6A 08 A3 ?4 ?? 42 00 E8 ?? 2A 00 00 A3 ?4 ?? 42 00 53 8D 44 24 34 68 60 01 00 00 50 53 68 ?? ?? 4? 00 FF 15 54 71 40 00 68 ?? 9? 40 00 }
	condition:
		$1 at pe.entry_point
}

rule nsis_230
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Nullsoft Install System"
		version = "2.30"
		source = "Made by Retdec Team"
	strings:
		$1 = { 81 EC 80 01 00 00 53 55 56 33 DB 57 89 5C 24 18 C7 44 24 10 ?? 91 40 00 33 F6 C6 44 24 14 20 FF 15 30 70 40 00 68 01 80 00 00 FF 15 B? 70 40 00 53 FF 15 7C 72 40 00 6A 08 A3 ?4 ?? ?? 00 E8 ?? 2A 00 00 A3 ?4 ?? ?? 00 53 8D 44 24 34 68 60 01 00 00 50 53 68 ?? ?? ?? 00 FF 15 58 71 40 00 68 ?? 9? 40 00 }
	condition:
		$1 at pe.entry_point
}

rule nsis_231_246
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Nullsoft Install System"
		version = "2.31 - 2.46"
		source = "Made by Retdec Team"
	strings:
		$1 = { 81 EC 80 01 00 00 53 55 56 33 DB 57 89 5C 24 18 C7 44 24 10 ?? ?? 40 00 33 F6 C6 44 24 14 20 FF 15 30 ?0 40 00 68 01 80 00 00 FF 15 B? ?0 40 00 53 FF 15 ?? ?2 40 00 6A 08 A3 ?8 ?? ?? 00 E8 ?? 2? 00 00 A3 ?4 ?? ?? 00 53 8D 44 24 34 68 60 01 00 00 50 53 68 ?? ?? ?? 00 FF 15 58 ?1 40 00 68 ?? ?? 40 00 }
	condition:
		$1 at pe.entry_point
}

rule nsis_247_248
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Nullsoft Install System"
		version = "2.47 - 2.48"
		source = "Made by Retdec Team"
	strings:
		$1 = { 81 EC 80 01 00 00 53 55 56 33 DB 57 89 5C 24 18 C7 44 24 10 ?? 91 40 00 33 F6 C6 44 24 14 20 FF 15 34 70 40 00 68 01 80 00 00 FF 15 B? 70 40 00 53 FF 15 70 72 40 00 53 A3 ?8 ?? ?? 00 E8 ?? 2D 00 00 3B C3 74 07 68 00 0C 00 00 FF D0 6A 0D E8 ?? 2D 00 00 6A 0B E8 ?? 2D 00 00 A3 ?4 ?? ?? 00 53 8D 44 24 }
	condition:
		$1 at pe.entry_point
}

rule nsis_249
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Nullsoft Install System"
		version = "2.49"
		source = "Made by Retdec Team"
	strings:
		$1 = { 81 EC 80 01 00 00 53 55 56 33 DB 57 89 5C 24 18 C7 44 24 10 ?? ?? 40 00 33 F6 C6 44 24 14 20 FF 15 34 70 40 00 68 01 80 00 00 FF 15 B? 70 40 00 53 FF 15 70 72 40 00 A3 ?8 ?? 4? 00 FF 15 B? 70 40 00 66 ?? ?? 0? 74 11 53 E8 ?? 2? 00 00 3B C3 74 07 68 00 0C 00 00 FF D0 6A 0D E8 ?? 2? 00 00 6A 0B E8 }
	condition:
		$1 at pe.entry_point
}

rule nsis_250
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Nullsoft Install System"
		version = "2.50"
		source = "Made by Retdec Team"
	strings:
		$1 = { 81 EC 80 01 00 00 53 55 56 57 33 DB 68 01 80 00 00 89 5C 24 1C C7 44 24 14 ?? 91 40 00 33 F6 C6 44 24 18 20 FF 15 B? 70 40 00 FF 15 B? 70 40 00 66 3D 06 00 74 11 53 E8 ?? 2D 00 00 3B C3 74 07 68 00 0C 00 00 FF D0 68 ?? 91 40 00 E8 ?? 2D 00 00 68 ?? 91 40 00 E8 ?? 2D 00 00 68 ?? 91 40 00 E8 ?? 2D 00 }
	condition:
		$1 at pe.entry_point
}

rule nsis_251
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Nullsoft Install System"
		version = "2.51"
		source = "Made by Retdec Team"
	strings:
		$1 = { 81 EC 84 01 00 00 53 55 56 57 33 DB 68 01 80 00 00 89 5C 24 20 C7 44 24 14 ?? ?? 40 00 89 5C 24 1C C6 44 24 18 20 FF 15 B? ?0 40 00 FF 15 ?? ?0 40 00 66 3D 06 00 74 11 53 E8 ?? ?? 00 00 3B C3 74 07 68 00 0C 00 00 FF D0 ?? ?? ?? ?? ?0 ?? ?? ?? ?? ?0 00 ?? ?? ?? ?? ?? ?? 00 }
	condition:
		$1 at pe.entry_point
}

rule nsis_300_301
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Nullsoft Install System"
		version = "3.00 - 3.01"
		source = "Made by Retdec Team"
	strings:
		$1 = { 81 EC 84 01 00 00 53 56 57 33 DB 68 01 80 00 00 89 5C 24 18 C7 44 24 10 ?? ?1 40 00 89 5C 24 20 C6 44 24 14 20 FF 15 ?? ?? 40 00 FF 15 A? ?0 40 00 66 3D 06 00 74 11 53 E8 ?? 2F 00 00 3B C3 74 07 68 00 0C 00 00 FF D0 BE 98 ?2 40 00 56 E8 ?? 2? 00 00 56 FF 15 A? ?0 40 00 8D 74 06 01 38 1E 75 EB 55 6A }
	condition:
		$1 at pe.entry_point
}

rule nsis_300_301_unicode
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Nullsoft Install System"
		version = "3.00 - 3.01"
		description = "unicode version"
		source = "Made by Retdec Team"
	strings:
		$1 = { 81 EC D4 02 00 00 53 56 57 6A 20 5F 33 DB 68 01 80 00 00 89 5C 24 14 C7 44 24 10 ?0 ?2 40 00 89 5C 24 1C FF 15 B? ?0 40 00 FF 15 ?? ?0 40 00 66 3D 06 00 74 11 53 E8 ?? 31 00 00 3B C3 74 07 68 00 0C 00 00 FF D0 BE B8 ?2 40 00 56 E8 ?? 30 00 00 56 FF 15 5C ?1 40 00 8D 74 06 01 80 3E 00 75 EA 55 6A 09 }
	condition:
		$1 at pe.entry_point
}

rule nsis_302
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Nullsoft Install System"
		version = "3.02"
		source = "Made by Retdec Team"
	strings:
		$1 = { 81 EC 84 01 00 00 53 56 57 33 DB 68 01 80 00 00 89 5C 24 18 C7 44 24 10 ?? ?1 40 00 89 5C 24 20 C6 44 24 14 20 FF 15 A? ?0 40 00 FF 15 ?? ?0 40 00 25 FF FF FF BF 66 3D 06 00 A3 ?C ?? ?? 00 74 11 53 E8 ?? 30 00 00 3B C3 74 07 68 00 0C 00 00 FF D0 BE 98 ?2 40 00 56 E8 ?? 30 00 00 56 FF 15 ?? ?0 40 00 }
	condition:
		$1 at pe.entry_point
}

rule nsis_302_unicode
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Nullsoft Install System"
		version = "3.02"
		description = "unicode version"
		source = "Made by Retdec Team"
	strings:
		$1 = { 81 EC D4 02 00 00 53 56 57 6A 20 5F 33 DB 68 01 80 00 00 89 5C 24 14 C7 44 24 10 ?0 A2 40 00 89 5C 24 1C FF 15 A? 80 40 00 FF 15 A? 80 40 00 25 FF FF FF BF 66 3D 06 00 A3 ?C ?? ?? 00 74 11 53 E8 ?? 32 00 00 3B C3 74 07 68 00 0C 00 00 FF D0 BE B0 82 40 00 56 E8 ?? 32 00 00 56 FF 15 50 81 40 00 8D 74 }
	condition:
		$1 at pe.entry_point
}

rule inno_uv {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 ?? 53 56 57 33 C0 89 45 F0 89 45 ?? 89 45 ?? E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF }
	condition:
		$1 at pe.entry_point
}

rule inno_10x {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "1.0.x"
	strings:
		$1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 A7 7F FF FF E8 FA 92 FF FF E8 F1 B3 FF FF 33 C0 }
	condition:
		$1 at pe.entry_point
}

rule inno_12x {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "1.2.x"
	strings:
		$1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 EC 89 45 C0 E8 5B 73 FF FF E8 D6 87 FF FF E8 C5 A9 FF FF E8 E0 }
	condition:
		$1 at pe.entry_point
}

rule inno_13x
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "1.3.x"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 43 73 FF FF E8 F2 87 FF FF E8 E1 A9 FF FF E8 A4 F6 FF FF E8 23 FC FF FF BE ?? FE 40 00 33 C0 55 68 65 C2 40 00 64 FF 30 64 89 20 33 D2 55 68 24 C2 40 00 64 FF 32 64 89 22 8D 55 F0 33 C0 E8 CC F3 FF FF 8B 55 F0 B8 ?? ?? 40 00 E8 03 74 FF }
		$2 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 C3 71 FF FF E8 72 86 FF FF E8 89 A8 FF FF E8 4C F5 FF FF E8 CB FA FF FF BE 78 FE 40 00 33 C0 55 68 51 C4 40 00 64 FF 30 64 89 20 33 D2 55 68 10 C4 40 00 64 FF 32 64 89 22 8D 55 F0 33 C0 E8 74 F2 FF FF 8B 55 F0 B8 DC FB 40 00 E8 83 72 FF }
		$3 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 43 73 FF FF E8 F2 87 FF FF E8 E1 A9 FF FF E8 A4 F6 FF FF E8 23 FC FF FF BE 74 FE 40 00 33 C0 55 68 65 C2 40 00 64 FF 30 64 89 20 33 D2 55 68 24 C2 40 00 64 FF 32 64 89 22 8D 55 F0 33 C0 E8 CC F3 FF FF 8B 55 F0 B8 D8 FB 40 00 E8 03 74 FF }
	condition:
		$1 at pe.entry_point or
		$2 at pe.entry_point or
		$3 at pe.entry_point
}

rule inno_overlay
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "1.3.x overlay"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 ?? 53 56 57 33 C0 89 45 ?? 89 45 }
	condition:
		$1 at pe.entry_point and
		pe.overlay.offset != 0 and
		pe.overlay.size > 0x10 and
		uint32(pe.overlay.offset) == 0x6B736469 and
		uint32(pe.overlay.offset+0x04) == 0x1A323361 and
		uint32(pe.overlay.offset+0x08) < filesize and
		uint32(pe.overlay.offset+0x0C) == 0x1A626C7A
}

rule inno_2xx
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "2.0.x"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 73 71 FF FF E8 DA 85 FF FF E8 81 A7 FF FF E8 C8 A7 FF FF E8 B7 A8 FF FF E8 36 F5 FF FF E8 F1 FA FF FF BE 04 FF 40 00 33 C0 55 68 E9 C4 40 00 64 FF 30 64 89 20 33 D2 55 68 A8 C4 40 00 64 FF 32 64 89 22 8D 55 F0 33 C0 E8 7A F2 FF FF 8B 55 }
	condition:
		$1 at pe.entry_point
}

rule inno_300b
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "3.0.0b"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 93 71 FF FF E8 FA 85 FF FF E8 99 A7 FF FF E8 E0 A7 FF FF E8 CF A8 FF FF E8 F6 FA FF FF BE 1C FF 40 00 33 C0 55 68 C4 C4 40 00 64 FF 30 64 89 20 33 D2 55 68 83 C4 40 00 64 FF 32 64 89 22 8D 55 F0 33 C0 E8 97 F2 FF FF 8B 55 F0 B8 80 FC 40 }
	condition:
		$1 at pe.entry_point
}

rule inno_301b
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "3.0.1b"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 2F 71 FF FF E8 96 85 FF FF E8 35 A7 FF FF E8 7C A7 FF FF E8 6B A8 FF FF E8 F6 FA FF FF BE 20 FF 40 00 33 C0 55 68 28 C5 40 00 64 FF 30 64 89 20 33 D2 55 68 E7 C4 40 00 64 FF 32 64 89 22 8D 55 F0 33 C0 E8 97 F2 FF FF 8B 55 F0 B8 84 FC 40 }
	condition:
		$1 at pe.entry_point
}

rule inno_302b
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "3.0.2b"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 2F 71 FF FF E8 96 85 FF FF E8 35 A7 FF FF E8 7C A7 FF FF E8 6B A8 FF FF E8 F6 FA FF FF BE 24 FF 40 00 33 C0 55 68 28 C5 40 00 64 FF 30 64 89 20 33 D2 55 68 E7 C4 40 00 64 FF 32 64 89 22 8D 55 F0 33 C0 E8 97 F2 FF FF 8B 55 F0 B8 88 FC 40 }
	condition:
		$1 at pe.entry_point
}

rule inno_303b
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "3.0.3b"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 B3 70 FF FF E8 1A 85 FF FF E8 25 A7 FF FF E8 6C A7 FF FF E8 5B A8 FF FF E8 E6 FA FF FF BE 20 FF 40 00 33 C0 55 68 C8 C5 40 00 64 FF 30 64 89 20 33 D2 55 68 58 C5 40 00 64 FF 32 64 89 22 8D 55 F0 33 C0 E8 87 F2 FF FF 8B 55 F0 B8 84 FC 40 }
	condition:
		$1 at pe.entry_point
}

rule inno_304b_307
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "3.0.4b - 3.0.7"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 B3 70 FF FF E8 1A 85 FF FF E8 25 A7 FF FF E8 6C A7 FF FF E8 5B A8 FF FF E8 E6 FA FF FF BE 24 FF 40 00 33 C0 55 68 C8 C5 40 00 64 FF 30 64 89 20 33 D2 55 68 58 C5 40 00 64 FF 32 64 89 22 8D 55 F0 33 C0 E8 87 F2 FF FF 8B 55 F0 B8 88 FC 40 }
	condition:
		$1 at pe.entry_point
}

rule inno_400
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "4.0.0"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 2F 6B FF FF E8 12 80 FF FF E8 85 A2 FF FF E8 CC A2 FF FF E8 BB A3 FF FF E8 2E F6 FF FF BE 34 FF 40 00 33 C0 55 68 15 CC 40 00 64 FF 30 64 89 20 33 D2 55 68 A5 CB 40 00 64 FF 32 64 89 22 A1 14 F0 40 00 E8 E7 FE FF FF E8 C6 F9 FF FF 8D 55 }
	condition:
		$1 at pe.entry_point
}

rule inno_401_402
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "4.0.1 - 4.0.2"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 13 6B FF FF E8 F6 7F FF FF E8 71 A2 FF FF E8 B8 A2 FF FF E8 A7 A3 FF FF E8 12 F6 FF FF BE 28 00 41 00 33 C0 55 68 34 CC 40 00 64 FF 30 64 89 20 33 D2 55 68 C4 CB 40 00 64 FF 32 64 89 22 A1 14 F0 40 00 E8 E7 FE FF FF E8 AA F9 FF FF 8D 55 }
	condition:
		$1 at pe.entry_point
}

rule inno_403_408
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "4.0.3 - 4.0.8"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 CF 6A FF FF E8 B2 7F FF FF E8 2D A2 FF FF E8 74 A2 FF FF E8 63 A3 FF FF E8 12 F6 FF FF BE 28 00 41 00 33 C0 55 68 DF CC 40 00 64 FF 30 64 89 20 33 D2 55 68 6F CC 40 00 64 FF 32 64 89 22 A1 14 F0 40 00 E8 E7 FE FF FF E8 AA F9 FF FF 8D 55 }
	condition:
		$1 at pe.entry_point
}

rule inno_409
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "4.0.9"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 9B 6A FF FF E8 7E 7F FF FF E8 F9 A1 FF FF E8 40 A2 FF FF E8 2F A3 FF FF E8 12 F6 FF FF BE 28 00 41 00 33 C0 55 68 13 CD 40 00 64 FF 30 64 89 20 33 D2 55 68 A3 CC 40 00 64 FF 32 64 89 22 A1 14 F0 40 00 E8 E7 FE FF FF E8 AA F9 FF FF 8D 55 }
	condition:
		$1 at pe.entry_point
}

rule inno_4010
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "4.0.10"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 93 6A FF FF E8 76 7F FF FF E8 F1 A1 FF FF E8 38 A2 FF FF E8 27 A3 FF FF E8 0A F6 FF FF BE 28 00 41 00 33 C0 55 68 32 CD 40 00 64 FF 30 64 89 20 33 D2 55 68 C2 CC 40 00 64 FF 32 64 89 22 A1 14 F0 40 00 E8 E7 FE FF FF E8 A2 F9 FF FF 8D 55 }
	condition:
		$1 at pe.entry_point
}

rule inno_4011
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "4.0.11"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 5F 6A FF FF E8 42 7F FF FF E8 BD A1 FF FF E8 04 A2 FF FF E8 F3 A2 FF FF E8 0E F6 FF FF BE 28 00 41 00 33 C0 55 68 66 CD 40 00 64 FF 30 64 89 20 33 D2 55 68 F6 CC 40 00 64 FF 32 64 89 22 A1 14 F0 40 00 E8 E7 FE FF FF E8 A6 F9 FF FF 8D 55 }
	condition:
		$1 at pe.entry_point
}

rule inno_410
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "4.1.0"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 57 6A FF FF E8 3A 7F FF FF E8 B5 A1 FF FF E8 FC A1 FF FF E8 EB A2 FF FF E8 06 F6 FF FF BE 2C 00 41 00 33 C0 55 68 6F CD 40 00 64 FF 30 64 89 20 33 D2 55 68 FF CC 40 00 64 FF 32 64 89 22 A1 14 F0 40 00 E8 E7 FE FF FF E8 9E F9 FF FF 8D 55 }
	condition:
		$1 at pe.entry_point
}

rule inno_411
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "4.1.1"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 57 6A FF FF E8 3A 7F FF FF E8 B5 A1 FF FF E8 FC A1 FF FF E8 EB A2 FF FF E8 06 F6 FF FF BE 38 00 41 00 33 C0 55 68 6F CD 40 00 64 FF 30 64 89 20 33 D2 55 68 FF CC 40 00 64 FF 32 64 89 22 A1 14 F0 40 00 E8 E7 FE FF FF E8 9E F9 FF FF 8D 55 }
	condition:
		$1 at pe.entry_point
}

rule inno_412_413
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "4.1.2 - 4.1.3"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 57 6A FF FF E8 3A 7F FF FF E8 B5 A1 FF FF E8 FC A1 FF FF E8 EB A2 FF FF E8 06 F6 FF FF BE 44 00 41 00 33 C0 55 68 6F CD 40 00 64 FF 30 64 89 20 33 D2 55 68 FF CC 40 00 64 FF 32 64 89 22 A1 14 F0 40 00 E8 E7 FE FF FF E8 9E F9 FF FF 8D 55 }
	condition:
		$1 at pe.entry_point
}

rule inno_414
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "4.1.4"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 57 6A FF FF E8 3A 7F FF FF E8 B5 A1 FF FF E8 FC A1 FF FF E8 EB A2 FF FF E8 06 F6 FF FF BE 4C 00 41 00 33 C0 55 68 6F CD 40 00 64 FF 30 64 89 20 33 D2 55 68 FF CC 40 00 64 FF 32 64 89 22 A1 14 F0 40 00 E8 E7 FE FF FF E8 9E F9 FF FF 8D 55 }
	condition:
		$1 at pe.entry_point
}

rule inno_415
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "4.1.5"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 57 6A FF FF E8 3A 7F FF FF E8 B5 A1 FF FF E8 FC A1 FF FF E8 EB A2 FF FF E8 06 F6 FF FF BE 50 00 41 00 33 C0 55 68 6F CD 40 00 64 FF 30 64 89 20 33 D2 55 68 FF CC 40 00 64 FF 32 64 89 22 A1 14 F0 40 00 E8 E7 FE FF FF E8 9E F9 FF FF 8D 55 }
	condition:
		$1 at pe.entry_point
}

rule inno_416_417
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "4.1.6 - 4.1.7"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 63 9F FF FF E8 46 B4 FF FF E8 C1 D6 FF FF E8 08 D7 FF FF E8 0B F6 FF FF BE 2C C0 40 00 33 C0 55 68 8E 98 40 00 64 FF 30 64 89 20 33 D2 55 68 1E 98 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EC FE FF FF E8 A3 F9 FF FF 8D 55 F0 33 C0 E8 ED }
	condition:
		$1 at pe.entry_point
}

rule inno_418
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "4.1.8"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 63 9F FF FF E8 46 B4 FF FF E8 C1 D6 FF FF E8 08 D7 FF FF E8 0B F6 FF FF BE 34 C0 40 00 33 C0 55 68 8E 98 40 00 64 FF 30 64 89 20 33 D2 55 68 1E 98 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EC FE FF FF E8 A3 F9 FF FF 8D 55 F0 33 C0 E8 ED }
	condition:
		$1 at pe.entry_point
}

rule inno_420
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "4.2.0"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 A7 9E FF FF E8 D2 B0 FF FF E8 29 D3 FF FF E8 70 D3 FF FF E8 0B F6 FF FF BE B0 BD 40 00 33 C0 55 68 CD 98 40 00 64 FF 30 64 89 20 33 D2 55 68 5D 98 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EC FE FF FF E8 A3 F9 FF FF 8D 55 F0 33 C0 E8 81 }
	condition:
		$1 at pe.entry_point
}

rule inno_421
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "4.2.1"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 9B 9E FF FF E8 C6 B0 FF FF E8 1D D3 FF FF E8 64 D3 FF FF E8 FF F5 FF FF BE B4 BD 40 00 33 C0 55 68 D9 98 40 00 64 FF 30 64 89 20 33 D2 55 68 69 98 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EC FE FF FF E8 97 F9 FF FF 8D 55 F0 33 C0 E8 75 }
	condition:
		$1 at pe.entry_point
}

rule inno_422_423
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "4.2.2 - 4.2.3"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 A3 9E FF FF E8 CE B0 FF FF E8 25 D3 FF FF E8 6C D3 FF FF E8 07 F6 FF FF BE BC BD 40 00 33 C0 55 68 D0 98 40 00 64 FF 30 64 89 20 33 D2 55 68 60 98 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EC FE FF FF E8 9F F9 FF FF 8D 55 F0 33 C0 E8 7D }
	condition:
		$1 at pe.entry_point
}

rule inno_424_426
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "4.2.4 -4.2.6"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 97 9E FF FF E8 C2 B0 FF FF E8 21 D3 FF FF E8 68 D3 FF FF E8 07 F6 FF FF BE CC BD 40 00 33 C0 55 68 DC 98 40 00 64 FF 30 64 89 20 33 D2 55 68 6C 98 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EC FE FF FF E8 9F F9 FF FF 8D 55 F0 33 C0 E8 79 }
	condition:
		$1 at pe.entry_point
}

rule inno_427
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "4.2.7"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 5F 9E FF FF E8 8A B0 FF FF E8 E9 D2 FF FF E8 30 D3 FF FF E8 07 F6 FF FF BE CC BD 40 00 33 C0 55 68 14 99 40 00 64 FF 30 64 89 20 33 D2 55 68 A4 98 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EC FE FF FF E8 9F F9 FF FF 8D 55 F0 33 C0 E8 41 }
	condition:
		$1 at pe.entry_point
}

rule inno_500
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.0.0"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 27 9E FF FF E8 52 B0 FF FF E8 B9 D2 FF FF E8 00 D3 FF FF E8 07 F6 FF FF BE C8 BD 40 00 33 C0 55 68 72 99 40 00 64 FF 30 64 89 20 33 D2 55 68 02 99 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EC FE FF FF E8 9F F9 FF FF 8D 55 F0 33 C0 E8 11 }
	condition:
		$1 at pe.entry_point
}

rule inno_501_502
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.0.1 - 5.0.2"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 57 9D FF FF E8 8E AF FF FF E8 D9 D1 FF FF E8 20 D2 FF FF E8 FB F5 FF FF BE C8 BD 40 00 33 C0 55 68 21 9A 40 00 64 FF 30 64 89 20 33 D2 55 68 D2 99 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EC FE FF FF E8 9F F9 FF FF 8D 55 F0 33 C0 E8 8D }
	condition:
		$1 at pe.entry_point
}

rule inno_503
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.0.3"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 9F 9D FF FF E8 D6 AF FF FF E8 19 D2 FF FF E8 60 D2 FF FF E8 FB F5 FF FF BE C8 BD 40 00 33 C0 55 68 D9 99 40 00 64 FF 30 64 89 20 33 D2 55 68 8A 99 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EC FE FF FF E8 9F F9 FF FF 8D 55 F0 33 C0 E8 8D }
	condition:
		$1 at pe.entry_point
}

rule inno_504
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.0.4"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 4B 9D FF FF E8 82 AF FF FF E8 C5 D1 FF FF E8 0C D2 FF FF E8 FB F5 FF FF BE C4 BD 40 00 33 C0 55 68 2D 9A 40 00 64 FF 30 64 89 20 33 D2 55 68 DE 99 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EC FE FF FF E8 9F F9 FF FF 8D 55 F0 33 C0 E8 39 }
	condition:
		$1 at pe.entry_point
}

rule inno_505_506
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.0.5 - 5.0.6"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 BB 9C FF FF E8 F2 AE FF FF E8 35 D1 FF FF E8 7C D1 FF FF E8 FB F5 FF FF BE C4 BD 40 00 33 C0 55 68 BD 9A 40 00 64 FF 30 64 89 20 33 D2 55 68 6E 9A 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EC FE FF FF E8 9F F9 FF FF 8D 55 F0 33 C0 E8 15 }
	condition:
		$1 at pe.entry_point
}

rule inno_507
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.0.7"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 9F 9C FF FF E8 D6 AE FF FF E8 19 D1 FF FF E8 60 D1 FF FF E8 DF F5 FF FF BE C4 BD 40 00 33 C0 55 68 E3 9A 40 00 64 FF 30 64 89 20 33 D2 55 68 94 9A 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EC FE FF FF E8 9F F9 FF FF 8D 55 F0 33 C0 E8 F9 }
	condition:
		$1 at pe.entry_point
}

rule inno_508
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.0.8"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 D4 53 56 57 33 C0 89 45 F0 89 45 E4 E8 E2 9B FF FF E8 8D AE FF FF E8 80 D0 FF FF E8 C7 D0 FF FF E8 DA F5 FF FF BE C4 BD 40 00 33 C0 55 68 C0 9B 40 00 64 FF 30 64 89 20 33 D2 55 68 76 9B 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EF FE FF FF E8 AE FA FF FF 8D 55 F0 33 C0 E8 40 D5 FF FF }
	condition:
		$1 at pe.entry_point
}

rule inno_510
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.1.0"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 D4 53 56 57 33 C0 89 45 F0 89 45 E4 E8 2E 9B FF FF E8 D9 AD FF FF E8 CC CF FF FF E8 13 D0 FF FF E8 52 F5 FF FF E8 31 F9 FF FF BE DC BD 40 00 33 C0 55 68 79 9C 40 00 64 FF 30 64 89 20 33 D2 55 68 2F 9C 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EA FE FF FF E8 A9 FA FF FF 8D 55 F0 33 C0 }
	condition:
		$1 at pe.entry_point
}

rule inno_511
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.1.1"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 D4 53 56 57 33 C0 89 45 F0 89 45 E4 E8 4A 9A FF FF E8 F5 AC FF FF E8 E8 CE FF FF E8 2F CF FF FF E8 6E F4 FF FF E8 5D F5 FF FF BE E0 BD 40 00 33 C0 55 68 61 9D 40 00 64 FF 30 64 89 20 33 D2 55 68 17 9D 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EA FE FF FF E8 A9 FA FF FF 8D 55 F0 33 C0 }
	condition:
		$1 at pe.entry_point
}

rule inno_512
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.1.2"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 D4 53 56 57 33 C0 89 45 F0 89 45 E4 E8 3A 9A FF FF E8 E5 AC FF FF E8 D8 CE FF FF E8 1F CF FF FF E8 6E F4 FF FF E8 5D F5 FF FF BE E0 BD 40 00 33 C0 55 68 71 9D 40 00 64 FF 30 64 89 20 33 D2 55 68 27 9D 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EA FE FF FF E8 A9 FA FF FF 8D 55 F0 33 C0 }
	condition:
		$1 at pe.entry_point
}

rule inno_513
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.1.3 - 5.1.4"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 D4 53 56 57 33 C0 89 45 F0 89 45 E4 E8 A6 98 FF FF E8 51 AB FF FF E8 54 CD FF FF E8 9B CD FF FF E8 92 F3 FF FF E8 F9 F4 FF FF BE E0 BD 40 00 33 C0 55 68 05 9F 40 00 64 FF 30 64 89 20 33 D2 55 68 BB 9E 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EA FE FF FF E8 A9 FA FF FF 8D 55 F0 33 C0 }
	condition:
		$1 at pe.entry_point
}

rule inno_516
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.1.5 - 5.1.6"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 CC 53 56 57 33 C0 89 45 F0 89 45 DC E8 D6 98 FF FF E8 DD AA FF FF E8 00 CD FF FF E8 47 CD FF FF E8 3E F3 FF FF E8 A5 F4 FF FF 33 C0 55 68 9A 9E 40 00 64 FF 30 64 89 20 33 D2 55 68 50 9E 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 9B FE FF FF E8 5A FA FF FF 8D 55 F0 33 C0 E8 C0 D1 FF FF }
	condition:
		$1 at pe.entry_point
}

rule inno_517
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.1.7"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 CC 53 56 57 33 C0 89 45 F0 89 45 DC E8 0A 98 FF FF E8 11 AA FF FF E8 3C CC FF FF E8 83 CC FF FF E8 0A F3 FF FF E8 71 F4 FF FF 33 C0 55 68 66 9F 40 00 64 FF 30 64 89 20 33 D2 55 68 1C 9F 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 9B FE FF FF E8 26 FA FF FF 8D 55 F0 33 C0 E8 FC D0 FF FF }
	condition:
		$1 at pe.entry_point
}

rule inno_518_519_5112
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.1.8 - 5.1.9, 5.1.12"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 CC 53 56 57 33 C0 89 45 F0 89 45 DC E8 EE 97 FF FF E8 F5 A9 FF FF E8 20 CC FF FF E8 67 CC FF FF E8 0A F3 FF FF E8 71 F4 FF FF 33 C0 55 68 82 9F 40 00 64 FF 30 64 89 20 33 D2 55 68 38 9F 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 9B FE FF FF E8 26 FA FF FF 8D 55 F0 33 C0 E8 E0 D0 FF FF }
	condition:
		$1 at pe.entry_point
}

rule inno_5110_5111
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.1.10 - 5.1.11"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 CC 53 56 57 33 C0 89 45 F0 89 45 DC E8 AA 97 FF FF E8 B1 A9 FF FF E8 DC CB FF FF E8 63 CC FF FF E8 0A F3 FF FF E8 71 F4 FF FF 33 C0 55 68 C6 9F 40 00 64 FF 30 64 89 20 33 D2 55 68 7C 9F 40 00 64 FF 32 64 89 22 A1 14 C0 40 00 E8 9B FE FF FF E8 26 FA FF FF 8D 55 F0 33 C0 E8 E0 D0 FF FF }
	condition:
		$1 at pe.entry_point
}

rule inno_5113_5114
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.1.13 - 5.1.14"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 CC 53 56 57 33 C0 89 45 F0 89 45 DC E8 FA 97 FF FF E8 01 AA FF FF E8 2C CC FF FF E8 73 CC FF FF E8 0A F3 FF FF E8 71 F4 FF FF 33 C0 55 68 76 9F 40 00 64 FF 30 64 89 20 33 D2 55 68 2C 9F 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 9B FE FF FF E8 26 FA FF FF 8D 55 F0 33 C0 E8 E0 D0 FF FF }
	condition:
		$1 at pe.entry_point
}

rule inno_520_521 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.2.0 - 5.2.1"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 C4 53 56 57 33 C0 89 45 F0 89 45 DC E8 3A 97 FF FF E8 41 A9 FF FF E8 6C CB FF FF E8 B3 CB FF FF E8 12 F3 FF FF E8 79 F4 FF FF 33 C0 55 68 32 A0 40 00 64 FF 30 64 89 20 33 D2 55 68 FB 9F 40 00 64 FF 32 64 89 22 A1 14 C0 40 00 E8 9B FE FF FF E8 06 FA FF FF 8D 55 F0 33 C0 E8 B0 D0 FF FF }
	condition:
		$1 at pe.entry_point
}

rule inno_522
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.2.2"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 C4 53 56 57 33 C0 89 45 F0 89 45 DC E8 72 96 FF FF E8 79 A8 FF FF E8 A4 CA FF FF E8 EB CA FF FF E8 12 F3 FF FF E8 79 F4 FF FF 33 C0 55 68 02 A1 40 00 64 FF 30 64 89 20 33 D2 55 68 CB A0 40 00 64 FF 32 64 89 22 A1 14 C0 40 00 E8 9B FE FF FF E8 06 FA FF FF 8D 55 F0 33 C0 E8 B0 D0 FF FF }
	condition:
		$1 at pe.entry_point
}

rule inno_523
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.2.3"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 C4 53 56 57 33 C0 89 45 F0 89 45 DC E8 6E 96 FF FF E8 75 A8 FF FF E8 A0 CA FF FF E8 E7 CA FF FF E8 0E F3 FF FF E8 75 F4 FF FF 33 C0 55 68 0B A1 40 00 64 FF 30 64 89 20 33 D2 55 68 D4 A0 40 00 64 FF 32 64 89 22 A1 14 C0 40 00 E8 9B FE FF FF E8 02 FA FF FF 8D 55 F0 33 C0 E8 AC D0 FF FF }
	condition:
		$1 at pe.entry_point
}

rule inno_530b_538
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.3.0b - 5.3.8"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 C4 53 56 57 33 C0 89 45 F0 89 45 DC E8 A2 95 FF FF E8 A9 A7 FF FF E8 D4 C9 FF FF E8 1B CA FF FF E8 0E F3 FF FF E8 75 F4 FF FF 33 C0 55 68 DB A1 40 00 64 FF 30 64 89 20 33 D2 55 68 A4 A1 40 00 64 FF 32 64 89 22 A1 14 C0 40 00 E8 9B FE FF FF E8 02 FA FF FF 8D 55 F0 33 C0 E8 04 D0 FF FF }
	condition:
		$1 at pe.entry_point
}

rule inno_539_5311
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.3.9 - 5.3.11"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 C4 53 56 57 33 C0 89 45 F0 89 45 DC E8 66 95 FF FF E8 6D A7 FF FF E8 98 C9 FF FF E8 DF C9 FF FF E8 0E F3 FF FF E8 75 F4 FF FF 33 C0 55 68 17 A2 40 00 64 FF 30 64 89 20 33 D2 55 68 E0 A1 40 00 64 FF 32 64 89 22 A1 14 C0 40 00 E8 9B FE FF FF E8 02 FA FF FF 8D 55 F0 33 C0 E8 C8 CF FF FF }
	condition:
		$1 at pe.entry_point
}

rule inno_5311
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.3.11"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 C4 53 56 57 33 C0 89 45 F0 89 45 DC E8 AE 94 FF FF E8 B5 A6 FF FF E8 44 A9 FF FF E8 53 C9 FF FF E8 9A C9 FF FF E8 C9 F2 FF FF E8 30 F4 FF FF 33 C0 55 68 D4 A2 40 00 64 FF 30 64 89 20 33 D2 55 68 9D A2 40 00 64 FF 32 64 89 22 A1 14 C0 40 00 E8 96 FE FF FF E8 C9 FA FF FF 8D 55 F0 33 C0 }
	condition:
		$1 at pe.entry_point
}

rule inno_540_551
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.4.0 - 5.5.1"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 C4 53 56 57 33 C0 89 45 F0 89 45 DC E8 86 94 FF FF E8 8D A6 FF FF E8 1C A9 FF FF E8 53 C9 FF FF E8 9A C9 FF FF E8 C9 F2 FF FF E8 30 F4 FF FF 33 C0 55 68 FC A2 40 00 64 FF 30 64 89 20 33 D2 55 68 C5 A2 40 00 64 FF 32 64 89 22 A1 14 C0 40 00 E8 96 FE FF FF E8 C9 FA FF FF 8D 55 F0 33 C0 }
	condition:
		$1 at pe.entry_point
}

rule inno_552
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.5.2"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 C4 53 56 57 33 C0 89 45 F0 89 45 DC E8 86 94 FF FF E8 8D A6 FF FF E8 1C A9 FF FF E8 BF A9 FF FF E8 5E C9 FF FF E8 C9 F2 FF FF E8 30 F4 FF FF 33 C0 55 68 FC A2 40 00 64 FF 30 64 89 20 33 D2 55 68 C5 A2 40 00 64 FF 32 64 89 22 A1 14 C0 40 00 E8 96 FE FF FF E8 C9 FA FF FF 8D 55 F0 33 C0 }
	condition:
		$1 at pe.entry_point
}

rule inno_553_558
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.5.3 - 5.5.8"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 C4 53 56 57 33 C0 89 45 F0 89 45 DC E8 CE 8A FF FF E8 D5 9C FF FF E8 64 9F FF FF E8 07 A0 FF FF E8 A6 BF FF FF E8 11 E9 FF FF E8 78 EA FF FF 33 C0 55 68 C9 AC 40 00 64 FF 30 64 89 20 33 D2 55 68 92 AC 40 00 64 FF 32 64 89 22 A1 14 C0 40 00 E8 26 F5 FF FF E8 11 F1 FF FF 80 3D 34 B2 40 }
	condition:
		$1 at pe.entry_point
}

rule inno_559
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.5.9"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 C4 53 56 57 33 C0 89 45 F0 89 45 DC E8 2E 86 FF FF E8 35 98 FF FF E8 9C 9B FF FF E8 B7 9F FF FF E8 56 BF FF FF E8 ED E8 FF FF E8 54 EA FF FF 33 C0 55 68 69 B1 40 00 64 FF 30 64 89 20 33 D2 55 68 32 B1 40 00 64 FF 32 64 89 22 A1 14 D0 40 00 E8 26 F5 FF FF E8 11 F1 FF FF 80 3D 34 C2 40 }
	condition:
		$1 at pe.entry_point
}

rule inno_unicode_530b_535
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.3.0b - 5.3.5"
		description = "unicode version"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 A4 53 56 57 33 C0 89 45 C4 89 45 C0 89 45 A4 89 45 D0 89 45 C8 89 45 CC 89 45 D4 89 45 D8 89 45 EC B8 A4 52 41 00 E8 F0 02 FF FF 33 C0 55 68 89 6A 41 00 64 FF 30 64 89 20 33 D2 55 68 45 6A 41 00 64 FF 32 64 89 22 A1 18 AB 41 00 E8 F6 EC FF FF E8 01 E8 FF FF 8D 55 EC 33 C0 E8 83 86 FF }
	condition:
		$1 at pe.entry_point
}

rule inno_unicode_536_537
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.3.6 - 5.3.7"
		description = "unicode version"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 A4 53 56 57 33 C0 89 45 C4 89 45 C0 89 45 A4 89 45 D0 89 45 C8 89 45 CC 89 45 D4 89 45 D8 89 45 EC B8 E8 54 41 00 E8 70 04 FF FF 33 C0 55 68 91 6A 41 00 64 FF 30 64 89 20 33 D2 55 68 4D 6A 41 00 64 FF 32 64 89 22 A1 48 AB 41 00 E8 3A EF FF FF E8 45 EA FF FF 8D 55 EC 33 C0 E8 FB 87 FF }
	condition:
		$1 at pe.entry_point
}

rule inno_unicode_538
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.3.8"
		description = "unicode version"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 A4 53 56 57 33 C0 89 45 C4 89 45 C0 89 45 A4 89 45 D0 89 45 C8 89 45 CC 89 45 D4 89 45 D8 89 45 EC B8 E8 54 41 00 E8 70 04 FF FF 33 C0 55 68 91 6A 41 00 64 FF 30 64 89 20 33 D2 55 68 4D 6A 41 00 64 FF 32 64 89 22 A1 48 AB 41 00 E8 3A EF FF FF E8 45 EA FF FF 8D 55 EC 33 C0 E8 FB 87 FF }
	condition:
		$1 at pe.entry_point
}

rule inno_unicode_539_5310
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.3.9 - 5.3.10"
		description = "unicode version"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 A4 53 56 57 33 C0 89 45 C4 89 45 C0 89 45 A4 89 45 D0 89 45 C8 89 45 CC 89 45 D4 89 45 D8 89 45 EC B8 54 55 41 00 E8 70 04 FF FF 33 C0 55 68 91 6A 41 00 64 FF 30 64 89 20 33 D2 55 68 4D 6A 41 00 64 FF 32 64 89 22 A1 48 AB 41 00 E8 A6 EF FF FF E8 B1 EA FF FF 8D 55 EC 33 C0 E8 FB 87 FF }
	condition:
		$1 at pe.entry_point
}

rule inno_unicode_5311
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.3.11"
		description = "unicode version"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 A4 53 56 57 33 C0 89 45 C4 89 45 C0 89 45 A4 89 45 D0 89 45 C8 89 45 CC 89 45 D4 89 45 D8 89 45 EC B8 18 56 41 00 E8 E4 03 FF FF 33 C0 55 68 1D 6B 41 00 64 FF 30 64 89 20 33 D2 55 68 D9 6A 41 00 64 FF 32 64 89 22 A1 48 AB 41 00 E8 DE EF FF FF E8 85 EB FF FF 8D 55 EC 33 C0 E8 9F 87 FF }
	condition:
		$1 at pe.entry_point
}

rule inno_unicode_540_543
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.4.0 - 5.4.3"
		description = "unicode version"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 A4 53 56 57 33 C0 89 45 C4 89 45 C0 89 45 A4 89 45 D0 89 45 C8 89 45 CC 89 45 D4 89 45 D8 89 45 EC B8 B0 52 41 00 E8 AC 03 FF FF 33 C0 55 68 45 6B 41 00 64 FF 30 64 89 20 33 D2 55 68 01 6B 41 00 64 FF 32 64 89 22 A1 48 AB 41 00 E8 4E EC FF FF E8 F5 E7 FF FF 8D 55 EC 33 C0 E8 7F 84 FF }
	condition:
		$1 at pe.entry_point
}

rule inno_unicode_550_551
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.5.0 - 5.5.1"
		description = "unicode version"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 A4 53 56 57 33 C0 89 45 C4 89 45 C0 89 45 A4 89 45 D0 89 45 C8 89 45 CC 89 45 D4 89 45 D8 89 45 EC B8 B8 52 41 00 E8 AC 03 FF FF 33 C0 55 68 45 6B 41 00 64 FF 30 64 89 20 33 D2 55 68 01 6B 41 00 64 FF 32 64 89 22 A1 48 AB 41 00 E8 56 EC FF FF E8 FD E7 FF FF 8D 55 EC 33 C0 E8 7F 84 FF }
	condition:
		$1 at pe.entry_point
}

rule inno_unicode_552
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.5.2"
		description = "unicode version"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 A4 53 56 57 33 C0 89 45 C4 89 45 C0 89 45 A4 89 45 D0 89 45 C8 89 45 CC 89 45 D4 89 45 D8 89 45 EC B8 64 ED 40 00 E8 E8 71 FF FF 33 C0 55 68 89 FA 40 00 64 FF 30 64 89 20 33 D2 55 68 45 FA 40 00 64 FF 32 64 89 22 A1 48 3B 41 00 E8 BE F7 FF FF E8 65 F3 FF FF 8D 55 EC 33 C0 E8 F7 C3 FF }
	condition:
		$1 at pe.entry_point
}

rule inno_unicode_553_555
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.5.3 - 5.5.5"
		description = "unicode version"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 A4 53 56 57 33 C0 89 45 C4 89 45 C0 89 45 A4 89 45 D0 89 45 C8 89 45 CC 89 45 D4 89 45 D8 89 45 EC B8 2C 00 41 00 E8 E8 51 FF FF 33 C0 55 68 9E 1A 41 00 64 FF 30 64 89 20 33 D2 55 68 5A 1A 41 00 64 FF 32 64 89 22 A1 48 5B 41 00 E8 16 D8 FF FF E8 65 D3 FF FF 80 3D DC 2A 41 00 00 74 0C }
	condition:
		$1 at pe.entry_point
}

rule inno_unicode_556_558
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.5.6 - 5.5.8"
		description = "unicode version"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 A4 53 56 57 33 C0 89 45 C4 89 45 C0 89 45 A4 89 45 D0 89 45 C8 89 45 CC 89 45 D4 89 45 D8 89 45 EC B8 34 00 41 00 E8 E8 51 FF FF 33 C0 55 68 9E 1A 41 00 64 FF 30 64 89 20 33 D2 55 68 5A 1A 41 00 64 FF 32 64 89 22 A1 48 5B 41 00 E8 1E D8 FF FF E8 6D D3 FF FF 80 3D DC 2A 41 00 00 74 0C }
	condition:
		$1 at pe.entry_point
}

rule inno_unicode_559
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "5.5.9"
		description = "unicode version"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 A4 53 56 57 33 C0 89 45 C4 89 45 C0 89 45 A4 89 45 D0 89 45 C8 89 45 CC 89 45 D4 89 45 D8 89 45 EC B8 44 01 41 00 E8 C8 4D FF FF 33 C0 55 68 BE 1E 41 00 64 FF 30 64 89 20 33 D2 55 68 7A 1E 41 00 64 FF 32 64 89 22 A1 48 5B 41 00 E8 0E D5 FF FF E8 5D D0 FF FF 80 3D DC 2A 41 00 00 74 0C }
	condition:
		$1 at pe.entry_point
}

rule inno_unicode_600
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Inno Setup"
		version = "6.0.0"
		description = "unicode version"
		source = "Made by Retdec Team"
	strings:
		$s01 = { 55 8b ec 83 c4 a4 53 56 57 33 c0 89 45 c4 89 45 c0 89 45 a4 89 45 d0 89 45 c8 89 45 cc 89 45 d4 89 45 d8 89 45 ec b8 d8 10 4b 00 e8 b0 72 f5 ff 33 c0 55 68 de 65 4b 00 64 ff 30 64 89 20 33 d2 }
		$s10 = "Inno Setup Setup Data (6.0.0) (u)"
		$s11 = "Inno Setup Messages (6.0.0) (u)"
	condition:
		$s01 at pe.entry_point and
		all of ($s1*)
}

rule sevenzip_sfx_3xx_01
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "7-Zip SFX"
		version = "3.xx"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 6A FF 68 08 EA 41 00 68 20 7A 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 6C E1 41 00 33 D2 8A D4 89 15 4C 65 42 00 8B C8 81 E1 FF 00 00 00 89 0D 48 65 42 00 C1 E1 08 03 CA 89 0D 44 65 42 00 C1 E8 10 A3 40 65 42 00 6A 01 E8 DB 1D 00 00 59 85 C0 75 08 6A }
	condition:
		$1 at pe.entry_point
}

rule sevenzip_sfx_3xx_02
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "7-Zip SFX"
		version = "3.xx"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 6A FF 68 70 86 41 00 68 7C 25 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 70 81 41 00 33 D2 8A D4 89 15 60 F4 41 00 8B C8 81 E1 FF 00 00 00 89 0D 5C F4 41 00 C1 E1 08 03 CA 89 0D 58 F4 41 00 C1 E8 10 A3 54 F4 41 00 6A 01 E8 ED 1D 00 00 59 85 C0 75 08 6A }
	condition:
		$1 at pe.entry_point
}

rule sevenzip_sfx_3xx_03
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "7-Zip SFX"
		version = "3.xx"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 6A FF 68 08 36 41 00 68 34 0C 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 68 53 56 57 89 65 E8 33 DB 89 5D FC 6A 02 FF 15 F8 30 41 00 59 83 0D DC 79 41 00 FF 83 0D E0 79 41 00 FF FF 15 FC 30 41 00 8B 0D D4 79 41 00 89 08 FF 15 00 31 41 00 8B 0D D0 79 41 00 89 08 A1 04 31 41 00 8B }
	condition:
		$1 at pe.entry_point
}

rule sevenzip_sfx_42x
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "7-Zip SFX"
		version = "4.2x"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 6A FF 68 20 2D 42 00 68 ?C C3 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 84 21 42 00 33 D2 8A D4 89 15 90 B9 42 00 8B C8 81 E1 FF 00 00 00 89 0D 8C B9 42 00 C1 E1 08 03 CA 89 0D 88 B9 42 00 C1 E8 10 A3 84 B9 42 00 6A 01 E8 BD 1C 00 00 59 85 C0 75 08 6A }
	condition:
		$1 at pe.entry_point
}

rule sevenzip_sfx_43x_9xx
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "7-Zip SFX"
		version = "4.3x - 9.xx"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 6A FF 68 ?? ?? 4? 00 68 ?? ?? 4? 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 68 53 56 57 89 65 E8 33 DB 89 5D FC 6A 02 FF 15 ?? ?? 4? 00 59 83 0D ?? ?? 42 00 FF 83 0D ?? ?? 42 00 FF FF 15 ?? ?? 4? 00 8B 0D ?? ?? 42 00 89 08 FF 15 ?? ?? 4? 00 8B 0D ?? ?? 42 00 89 08 A1 ?? ?? 4? 00 8B }
	condition:
		$1 at pe.entry_point
}

rule sevenzip_sfx_15xx_16xx
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "7-Zip SFX"
		version = "15.xx - 16.xx"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 6A FF 68 ?? ?? 42 00 68 ?4 4? 42 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 68 53 56 57 89 65 E8 33 DB 89 5D FC 6A 02 FF 15 ?? ?1 42 00 59 83 0D 74 ?5 43 00 FF 83 0D 78 ?5 43 00 FF FF 15 ?? ?1 42 00 8B 0D 44 ?5 4? 00 89 08 FF 15 3? ?1 42 00 8B 0D 40 ?5 4? 00 89 08 A1 ?? ?1 42 00 8B }
	condition:
		$1 at pe.entry_point
}

rule sevenzip_sfx_17xx
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "7-Zip SFX"
		version = "17.xx"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 6A FF 68 50 9B 42 00 68 ?4 4E 42 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 68 53 56 57 89 65 E8 33 DB 89 5D FC 6A 02 FF 15 3C 81 42 00 59 83 0D 34 35 43 00 FF 83 0D 38 35 43 00 FF FF 15 38 81 42 00 8B 0D 14 15 43 00 89 08 FF 15 34 81 42 00 8B 0D 10 15 43 00 89 08 A1 30 81 42 00 8B }
	condition:
		$1 at pe.entry_point
}

rule sevenzip_sfx_313_console
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "7-Zip SFX"
		version = "3.13"
		description = "console version"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 6A FF 68 78 F8 41 00 68 60 7C 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 10 53 56 57 89 65 E8 FF 15 10 F1 41 00 33 D2 8A D4 89 15 2C 7E 42 00 8B C8 81 E1 FF 00 00 00 89 0D 28 7E 42 00 C1 E1 08 03 CA 89 0D 24 7E 42 00 C1 E8 10 A3 20 7E 42 00 6A 01 E8 FD 13 00 00 59 85 C0 75 08 6A }
	condition:
		$1 at pe.entry_point
}

rule sevenzip_sfx_42x_console
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "7-Zip SFX"
		version = "4.2x"
		description = "console version"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 6A FF 68 20 2C 42 00 68 ?0 CD 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 10 53 56 57 89 65 E8 FF 15 00 21 42 00 33 D2 8A D4 89 15 8C BF 42 00 8B C8 81 E1 FF 00 00 00 89 0D 88 BF 42 00 C1 E1 08 03 CA 89 0D 84 BF 42 00 C1 E8 10 A3 80 BF 42 00 6A 01 E8 9F 1C 00 00 59 85 C0 75 08 6A }
	condition:
		$1 at pe.entry_point
}

rule sevenzip_sfx_43x_16xx_console
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "7-Zip SFX"
		version = "4.3x - 16.xx"
		description = "console version"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 6A FF 68 ?? ?? 4? 00 68 ?? ?? 4? 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 20 53 56 57 89 65 E8 83 65 FC 00 6A 01 FF 15 ?? ?0 4? 00 59 83 0D ?? ?? 42 00 FF 83 0D ?? ?? 42 00 FF FF 15 ?? ?0 4? 00 8B 0D ?? ?? 42 00 89 08 FF 15 ?? ?0 4? 00 8B 0D ?? ?? 42 00 89 08 A1 ?? ?0 4? 00 8B 00 }
	condition:
		$1 at pe.entry_point
}

rule sevenzip_sfx_17xx_console
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "7-Zip SFX"
		version = "17.xx"
		description = "console version"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 6A FF 68 C0 76 42 00 68 ?C 2? 42 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 20 53 56 57 89 65 E8 83 65 FC 00 6A 01 FF 15 DC 50 42 00 59 83 0D 34 06 43 00 FF 83 0D 38 06 43 00 FF FF 15 E0 50 42 00 8B 0D FC E5 42 00 89 08 FF 15 E4 50 42 00 8B 0D F8 E5 42 00 89 08 A1 E8 50 42 00 8B 00 }
	condition:
		$1 at pe.entry_point
}

rule winxzip_sfx_uv_01 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinZip SFX"
	strings:
		$1 = { FF 15 ?? ?? ?? 00 B1 22 38 08 74 02 B1 20 40 80 38 00 74 10 }
	condition:
		$1 at pe.entry_point
}

rule winxzip_sfx_uv_02 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinZip SFX"
	strings:
		$1 = { 53 FF 15 ?? ?? ?? 00 B3 22 38 18 74 03 80 C3 FE 8A 48 01 40 33 D2 3A CA 74 0A 3A CB 74 06 8A 48 01 40 EB F2 38 10 }
	condition:
		$1 at pe.entry_point
}

rule winxzip_sfx_uv_03
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinZip SFX"
		source = "Made by Retdec Team"
	strings:
		$1 = { 53 FF 15 60 70 40 00 B3 22 38 18 74 03 80 C3 FE 40 8A 08 33 D2 3A CA 74 10 3A CB 74 07 40 8A 08 3A CA 75 F5 38 10 74 01 40 52 50 52 52 FF 15 64 70 40 00 50 E8 01 FC FF FF 50 FF 15 84 70 40 00 5B 55 8B EC 51 A1 9C 9? 40 00 83 0D 08 A? 40 00 FF 56 33 F6 39 35 44 9? 40 00 89 35 8C 9? 40 00 89 35 68 }
	condition:
		$1 at pe.entry_point
}

rule winzip_sfx_22_personal {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinZip SFX"
		version = "2.2"
		description = "personal edition"
	strings:
		$1 = { 53 FF 15 58 70 40 00 B3 22 38 18 74 03 80 C3 FE 40 33 D2 8A 08 3A CA 74 10 3A CB 74 07 40 8A 08 3A CA 75 F5 38 10 74 01 40 52 50 52 52 FF 15 5C 70 40 00 50 E8 15 FB FF FF 50 FF 15 8C 70 40 00 5B }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_uv_01
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
	strings:
		$1 = { 83 F8 08 7C 08 33 D2 89 15 ?? ?? 40 00 8B 0D ?? ?? 40 00 C1 E1 08 C6 81 ?? ?? 40 00 00 68 00 01 00 00 A1 ?? ?? 40 00 C1 E0 08 81 C0 ?? ?? 40 00 50 FF 75 08 FF 35 }
	condition:
		for any of them : ( $ in (pe.entry_point + 20 .. pe.entry_point + 24) )
}

rule winrar_sfx_uv_02
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
	strings:
		$1 = { E8 ?? ?? ?? ?? 33 C0 50 50 50 50 E8 ?? ?? ?? ?? C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_uv_03
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
	strings:
		$1 = { E8 ?? ?? ?? 00 50 E8 ?? ?? ?? 00 00 00 00 00 90 55 8B EC 53 56 57 8B 7D 10 8B 5D 0C 8B 75 08 8B D3 FF 75 14 68 ?? ?? ?? 00 6A 00 6A 00 8B C6 8B CF E8 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_uv_04
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
	strings:
		$1 = { E8 ?? ?? ?? 00 50 E8 ?? ?? ?? 00 00 00 00 00 90 55 8B EC 81 C4 F4 F3 FF FF }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_uv_05
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
	strings:
		$1 = { E8 ?? ?? ?? 00 50 E8 ?? ?? ?? 00 00 00 00 00 90 81 C4 F4 F3 FF FF }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_uv_06
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
	strings:
		$1 = { E8 ?? ?? ?? 00 C3 00 00 00 00 90 90 52 50 8B 44 24 10 F7 24 24 8B C8 8B 44 24 04 F7 64 24 0C 03 C8 8B 04 24 F7 64 24 0C 03 D1 59 59 C2 08 00 55 53 56 57 33 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_uv_07
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
	strings:
		$1 = { E9 ?? ?? 00 00 00 00 00 00 90 90 90 55 8B EC 53 56 57 8B 7D 10 8B 5D 0C 8B 75 08 8B D3 FF 75 14 68 DD ?? ?? 00 6A 00 6A 00 8B C6 8B CF E8 ?? ?? 00 00 81 EB 10 01 00 00 74 05 4B 74 14 EB 57 FF }
	condition:
		$1 at pe.entry_point
}

rule winrar_uv_08 {
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
	strings:
		$1 = { E9 ?? ?? 00 00 00 00 00 00 90 90 90 ?? ?? ?? ?? ?? ?? 00 ?? 00 ?? ?? ?? ?? ?? FF }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_35x
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "3.5x"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 9B 27 00 00 50 E8 A7 22 01 00 00 00 00 00 90 55 8B EC 53 56 57 8B 7D 10 8B 5D 0C 8B 75 08 8B D3 FF 75 14 68 E5 40 41 00 6A 00 6A 00 8B C6 8B CF E8 26 43 00 00 81 EB 10 01 00 00 74 05 4B 74 14 EB 57 FF 75 14 6A 66 56 E8 F8 24 01 00 B8 01 00 00 00 EB 47 66 81 E7 FF FF 66 FF CF 74 07 66 FF CF 74 23 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_361
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "3.61"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 9F 28 00 00 50 E8 83 2A 01 00 00 00 00 00 90 55 8B EC 53 56 57 8B 7D 10 8B 5D 0C 8B 75 08 8B D3 FF 75 14 68 E5 40 41 00 6A 00 6A 00 8B C6 8B CF E8 2A 44 00 00 81 EB 10 01 00 00 74 05 4B 74 14 EB 57 FF 75 14 6A 66 56 E8 DA 2C 01 00 B8 01 00 00 00 EB 47 66 81 E7 FF FF 66 FF CF 74 07 66 FF CF 74 23 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_362
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "3.62"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 8F 28 00 00 50 E8 CB 29 01 00 00 00 00 00 90 55 8B EC 53 56 57 8B 7D 10 8B 5D 0C 8B 75 08 8B D3 FF 75 14 68 E5 40 41 00 6A 00 6A 00 8B C6 8B CF E8 0A 44 00 00 81 EB 10 01 00 00 74 05 4B 74 14 EB 57 FF 75 14 6A 66 56 E8 22 2C 01 00 B8 01 00 00 00 EB 47 66 81 E7 FF FF 66 FF CF 74 07 66 FF CF 74 23 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_370
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "3.70"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 2F 2B 00 00 50 E8 3F 31 01 00 00 00 00 00 90 55 8B EC 53 56 57 8B 7D 10 8B 5D 0C 8B 75 08 8B D3 FF 75 14 68 E1 50 41 00 6A 00 6A 00 8B C6 8B CF E8 52 47 00 00 81 EB 10 01 00 00 74 05 4B 74 14 EB 57 FF 75 14 6A 66 56 E8 9E 33 01 00 B8 01 00 00 00 EB 47 66 81 E7 FF FF 66 FF CF 74 07 66 FF CF 74 23 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_371
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "3.71"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 F3 2A 00 00 50 E8 3B 33 01 00 00 00 00 00 90 55 8B EC 53 56 57 8B 7D 10 8B 5D 0C 8B 75 08 8B D3 FF 75 14 68 E1 50 41 00 6A 00 6A 00 8B C6 8B CF E8 A2 47 00 00 81 EB 10 01 00 00 74 05 4B 74 14 EB 57 FF 75 14 6A 66 56 E8 9A 35 01 00 B8 01 00 00 00 EB 47 66 81 E7 FF FF 66 FF CF 74 07 66 FF CF 74 23 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_380
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "3.80"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 6F 2B 00 00 50 E8 73 36 01 00 00 00 00 00 90 55 8B EC 53 56 57 8B 7D 10 8B 5D 0C 8B 75 08 8B D3 FF 75 14 68 E5 50 41 00 6A 00 6A 00 8B C6 8B CF E8 7A 48 00 00 81 EB 10 01 00 00 74 05 4B 74 14 EB 57 FF 75 14 6A 66 56 E8 DE 38 01 00 B8 01 00 00 00 EB 47 66 81 E7 FF FF 66 FF CF 74 07 66 FF CF 74 23 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_390
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "3.90"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 E3 FE FF FF 33 C0 50 50 50 50 E8 54 2B 00 00 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 E2 A7 FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 C1 AC FF FF C3 55 8B EC 83 EC 1C 56 33 F6 56 56 56 56 8D 45 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_391
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "3.91"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 E3 FE FF FF 33 C0 50 50 50 50 E8 BE 2B 00 00 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 E2 A7 FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 C1 AC FF FF C3 55 8B EC 83 EC 1C 56 33 F6 56 56 56 56 8D 45 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_392
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "3.92"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 E3 FE FF FF 33 C0 50 50 50 50 E8 BE 2B 00 00 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 F6 A7 FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 D5 AC FF FF C3 55 8B EC 83 EC 1C 56 33 F6 56 56 56 56 8D 45 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_393
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "3.93"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 E3 FE FF FF 33 C0 50 50 50 50 E8 BE 2B 00 00 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 D0 A7 FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 AF AC FF FF C3 55 8B EC 83 EC 1C 56 33 F6 56 56 56 56 8D 45 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_400
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "4.00"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 E3 FE FF FF 33 C0 50 50 50 50 E8 7F 2D 00 00 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 1E A1 FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 47 A6 FF FF C3 55 8B EC 83 EC 1C 56 33 F6 56 56 56 56 8D 45 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_401
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "4.01"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 E3 FE FF FF 33 C0 50 50 50 50 E8 D5 2D 00 00 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 F3 A0 FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 1C A6 FF FF C3 55 8B EC 83 EC 1C 56 33 F6 56 56 56 56 8D 45 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_410
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "4.10"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 E3 FE FF FF 33 C0 50 50 50 50 E8 F2 2D 00 00 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 B0 A1 FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 D9 A6 FF FF C3 55 8B EC 83 EC 1C 56 33 F6 56 56 56 56 8D 45 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_411
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "4.11"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 E3 FE FF FF 33 C0 50 50 50 50 E8 F2 2D 00 00 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 EE 9F FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 17 A5 FF FF C3 55 8B EC 83 EC 1C 56 33 F6 56 56 56 56 8D 45 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_420
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "4.20"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 E3 FE FF FF 33 C0 50 50 50 50 E8 9F 30 00 00 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 8F AB FF FF 89 46 08 89 56 0C 8B 87 24 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 24 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 0E B1 FF FF C3 56 8B F1 8B 06 85 C0 74 07 50 FF 15 C4 40 41 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_50x
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "5.0x"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 F0 57 00 00 E9 78 FE FF FF 8B FF 55 8B EC 56 8D 45 08 50 8B F1 E8 05 FD FF FF C7 06 ?4 81 42 00 8B C6 5E 5D C2 04 00 C7 01 ?4 81 42 00 E9 BA FD FF FF 8B FF 55 8B EC 56 8B F1 C7 06 ?4 81 42 00 E8 A7 FD FF FF F6 45 08 01 74 07 56 E8 ?? C9 FF FF 59 8B C6 5E 5D C2 04 00 8B FF 55 8B EC 56 57 8B 7D 08 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_510
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "5.10"
		source = "Made by Retdec Team"
		strings:
		$1 = { E8 5D 64 00 00 E9 78 FE FF FF 8B FF 55 8B EC 56 8D 45 08 50 8B F1 E8 7A FC FF FF C7 06 F0 B1 42 00 8B C6 5E 5D C2 04 00 C7 01 F0 B1 42 00 E9 2F FD FF FF 8B FF 55 8B EC 56 8B F1 C7 06 F0 B1 42 00 E8 1C FD FF FF F6 45 08 01 74 07 56 E8 86 C9 FF FF 59 8B C6 5E 5D C2 04 00 8B FF 55 8B EC 56 57 8B 7D 08 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_511
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "5.11"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 5C 64 00 00 E9 78 FE FF FF 8B FF 55 8B EC 56 8D 45 08 50 8B F1 E8 7A FC FF FF C7 06 20 B2 42 00 8B C6 5E 5D C2 04 00 C7 01 20 B2 42 00 E9 2F FD FF FF 8B FF 55 8B EC 56 8B F1 C7 06 20 B2 42 00 E8 1C FD FF FF F6 45 08 01 74 07 56 E8 86 C9 FF FF 59 8B C6 5E 5D C2 04 00 8B FF 55 8B EC 56 57 8B 7D 08 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_520
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "5.20"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 85 63 00 00 E9 78 FE FF FF 8B FF 55 8B EC 56 8D 45 08 50 8B F1 E8 82 FC FF FF C7 06 20 B2 42 00 8B C6 5E 5D C2 04 00 C7 01 20 B2 42 00 E9 37 FD FF FF 8B FF 55 8B EC 56 8B F1 C7 06 20 B2 42 00 E8 24 FD FF FF F6 45 08 01 74 07 56 E8 4E CA FF FF 59 8B C6 5E 5D C2 04 00 8B FF 55 8B EC 56 57 8B 7D 08 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_521
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "5.21"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 85 63 00 00 E9 78 FE FF FF 8B FF 55 8B EC 56 8D 45 08 50 8B F1 E8 82 FC FF FF C7 06 20 B2 42 00 8B C6 5E 5D C2 04 00 C7 01 20 B2 42 00 E9 37 FD FF FF 8B FF 55 8B EC 56 8B F1 C7 06 20 B2 42 00 E8 24 FD FF FF F6 45 08 01 74 07 56 E8 52 CA FF FF 59 8B C6 5E 5D C2 04 00 8B FF 55 8B EC 56 57 8B 7D 08 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_530
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "5.30"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 86 63 00 00 E9 78 FE FF FF 8B FF 55 8B EC 56 8D 45 08 50 8B F1 E8 82 FC FF FF C7 06 F0 B2 42 00 8B C6 5E 5D C2 04 00 C7 01 F0 B2 42 00 E9 37 FD FF FF 8B FF 55 8B EC 56 8B F1 C7 06 F0 B2 42 00 E8 24 FD FF FF F6 45 08 01 74 07 56 E8 8A CA FF FF 59 8B C6 5E 5D C2 04 00 8B FF 55 8B EC 56 57 8B 7D 08 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_531
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "5.31"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 DF 65 00 00 E9 78 FE FF FF 8B FF 55 8B EC 56 8D 45 08 50 8B F1 E8 82 FC FF FF C7 06 94 C8 42 00 8B C6 5E 5D C2 04 00 C7 01 94 C8 42 00 E9 37 FD FF FF 8B FF 55 8B EC 56 8B F1 C7 06 94 C8 42 00 E8 24 FD FF FF F6 45 08 01 74 07 56 E8 6A CA FF FF 59 8B C6 5E 5D C2 04 00 8B FF 55 8B EC 56 57 8B 7D 08 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_540
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "5.40"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 99 04 00 00 E9 80 FE FF FF 3B 0D B8 91 43 00 F2 75 02 F2 C3 F2 E9 0F 06 00 00 83 61 04 00 8B C1 83 61 08 00 C7 41 04 60 FF 42 00 C7 01 FC 08 43 00 C3 55 8B EC 56 FF 75 08 8B F1 E8 44 38 FF FF C7 06 08 09 43 00 8B C6 5E 5D C2 04 00 83 61 04 00 8B C1 83 61 08 00 C7 41 04 10 09 43 00 C7 01 08 09 43 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_550
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "5.50"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 8A 04 00 00 E9 8E FE FF FF 3B 0D B8 A1 43 00 F2 75 02 F2 C3 F2 E9 FF 05 00 00 83 61 04 00 8B C1 83 61 08 00 C7 41 04 60 0F 43 00 C7 01 04 19 43 00 C3 55 8B EC 56 FF 75 08 8B F1 E8 1C 3A FF FF C7 06 10 19 43 00 8B C6 5E 5D C2 04 00 83 61 04 00 8B C1 83 61 08 00 C7 41 04 18 19 43 00 C7 01 10 19 43 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_350
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "3.50"
		description = "with ZIP payload"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 B7 24 00 00 50 E8 E7 9D 00 00 00 00 00 00 90 55 8B EC 53 56 57 8B 7D 10 8B 5D 0C 8B 75 08 8B D3 FF 75 14 68 E5 C0 40 00 6A 00 6A 00 8B C6 8B CF E8 42 40 00 00 81 EB 10 01 00 00 74 05 4B 74 14 EB 57 FF 75 14 6A 66 56 E8 3C A0 00 00 B8 01 00 00 00 EB 47 66 81 E7 FF FF 66 FF CF 74 07 66 FF CF 74 23 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_351
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "3.51"
		description = "with ZIP payload"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 B7 24 00 00 50 E8 FB 9D 00 00 00 00 00 00 90 55 8B EC 53 56 57 8B 7D 10 8B 5D 0C 8B 75 08 8B D3 FF 75 14 68 E5 C0 40 00 6A 00 6A 00 8B C6 8B CF E8 42 40 00 00 81 EB 10 01 00 00 74 05 4B 74 14 EB 57 FF 75 14 6A 66 56 E8 50 A0 00 00 B8 01 00 00 00 EB 47 66 81 E7 FF FF 66 FF CF 74 07 66 FF CF 74 23 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "3.61"
		description = "with ZIP payload"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 B7 25 00 00 50 E8 47 9F 00 00 00 00 00 00 90 55 8B EC 53 56 57 8B 7D 10 8B 5D 0C 8B 75 08 8B D3 FF 75 14 68 E5 C0 40 00 6A 00 6A 00 8B C6 8B CF E8 42 41 00 00 81 EB 10 01 00 00 74 05 4B 74 14 EB 57 FF 75 14 6A 66 56 E8 9C A1 00 00 B8 01 00 00 00 EB 47 66 81 E7 FF FF 66 FF CF 74 07 66 FF CF 74 23 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_362
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "3.62"
		description = "with ZIP payload"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 A7 25 00 00 50 E8 0B 9F 00 00 00 00 00 00 90 55 8B EC 53 56 57 8B 7D 10 8B 5D 0C 8B 75 08 8B D3 FF 75 14 68 E5 C0 40 00 6A 00 6A 00 8B C6 8B CF E8 22 41 00 00 81 EB 10 01 00 00 74 05 4B 74 14 EB 57 FF 75 14 6A 66 56 E8 60 A1 00 00 B8 01 00 00 00 EB 47 66 81 E7 FF FF 66 FF CF 74 07 66 FF CF 74 23 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_370
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "3.70"
		description = "with ZIP payload"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 DB 27 00 00 50 E8 B7 A2 00 00 00 00 00 00 90 55 8B EC 53 56 57 8B 7D 10 8B 5D 0C 8B 75 08 8B D3 FF 75 14 68 E1 C0 40 00 6A 00 6A 00 8B C6 8B CF E8 FE 43 00 00 81 EB 10 01 00 00 74 05 4B 74 14 EB 57 FF 75 14 6A 66 56 E8 0C A5 00 00 B8 01 00 00 00 EB 47 66 81 E7 FF FF 66 FF CF 74 07 66 FF CF 74 23 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_371
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "3.71"
		description = "with ZIP payload"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 8B 27 00 00 50 E8 4F A4 00 00 00 00 00 00 90 55 8B EC 53 56 57 8B 7D 10 8B 5D 0C 8B 75 08 8B D3 FF 75 14 68 E1 C0 40 00 6A 00 6A 00 8B C6 8B CF E8 3A 44 00 00 81 EB 10 01 00 00 74 05 4B 74 14 EB 57 FF 75 14 6A 66 56 E8 A4 A6 00 00 B8 01 00 00 00 EB 47 66 81 E7 FF FF 66 FF CF 74 07 66 FF CF 74 23 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_380
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "3.80"
		description = "with ZIP payload"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 FB 27 00 00 50 E8 63 A6 00 00 00 00 00 00 90 55 8B EC 53 56 57 8B 7D 10 8B 5D 0C 8B 75 08 8B D3 FF 75 14 68 E5 C0 40 00 6A 00 6A 00 8B C6 8B CF E8 06 45 00 00 81 EB 10 01 00 00 74 05 4B 74 14 EB 57 FF 75 14 6A 66 56 E8 C0 A8 00 00 B8 01 00 00 00 EB 47 66 81 E7 FF FF 66 FF CF 74 07 66 FF CF 74 23 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_391
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "3.91"
		description = "with ZIP payload"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 1E FF FF FF 33 C0 50 50 50 50 E8 BF 2A 00 00 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 13 9E FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 7A A2 FF FF C3 55 8B EC 83 EC 1C 56 33 F6 56 56 56 56 8D 45 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_392
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "3.92"
		description = "with ZIP payload"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 1E FF FF FF 33 C0 50 50 50 50 E8 BF 2A 00 00 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 22 9E FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 89 A2 FF FF C3 55 8B EC 83 EC 1C 56 33 F6 56 56 56 56 8D 45 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_393
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "3.93"
		description = "with ZIP payload"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 1E FF FF FF 33 C0 50 50 50 50 E8 BF 2A 00 00 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 FC 9D FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 63 A2 FF FF C3 55 8B EC 83 EC 1C 56 33 F6 56 56 56 56 8D 45 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_400
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "4.00"
		description = "with ZIP payload"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 1E FF FF FF 33 C0 50 50 50 50 E8 EA 2B 00 00 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 AB 98 FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 55 9D FF FF C3 55 8B EC 83 EC 1C 56 33 F6 56 56 56 56 8D 45 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_401
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "4.01"
		description = "with ZIP payload"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 1E FF FF FF 33 C0 50 50 50 50 E8 40 2C 00 00 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 78 98 FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 22 9D FF FF C3 55 8B EC 83 EC 1C 56 33 F6 56 56 56 56 8D 45 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_411
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "4.11"
		description = "with ZIP payload"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 1E FF FF FF 33 C0 50 50 50 50 E8 5D 2C 00 00 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 DB 96 FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 D8 9A FF FF C3 55 8B EC 83 EC 1C 56 33 F6 56 56 56 56 8D 45 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_420
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "4.20"
		description = "with ZIP payload"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 1E FF FF FF 33 C0 50 50 50 50 E8 A4 2E 00 00 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 7D A2 FF FF 89 46 08 89 56 0C 8B 87 24 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 24 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 8F A7 FF FF C3 56 8B F1 8B 06 85 C0 74 07 50 FF 15 64 F1 40 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_501
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "5.01"
		description = "with ZIP payload"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 9C 58 00 00 E9 78 FE FF FF 55 8B EC 83 EC 04 89 7D FC 8B 7D 08 8B 4D 0C C1 E9 07 66 0F EF C0 EB 08 8D A4 24 00 00 00 00 90 66 0F 7F 07 66 0F 7F 47 10 66 0F 7F 47 20 66 0F 7F 47 30 66 0F 7F 47 40 66 0F 7F 47 50 66 0F 7F 47 60 66 0F 7F 47 70 8D BF 80 00 00 00 49 75 D0 8B 7D FC 8B E5 5D C3 55 8B EC }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_510
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "5.1x"
		description = "with ZIP payload"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 11 65 00 00 E9 78 FE FF FF 55 8B EC 83 EC 04 89 7D FC 8B 7D 08 8B 4D 0C C1 E9 07 66 0F EF C0 EB 08 8D A4 24 00 00 00 00 90 66 0F 7F 07 66 0F 7F 47 10 66 0F 7F 47 20 66 0F 7F 47 30 66 0F 7F 47 40 66 0F 7F 47 50 66 0F 7F 47 60 66 0F 7F 47 70 8D BF 80 00 00 00 49 75 D0 8B 7D FC 8B E5 5D C3 55 8B EC }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_52x
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "5.2x"
		description = "with ZIP payload"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 2D 64 00 00 E9 78 FE FF FF 55 8B EC 83 EC 04 89 7D FC 8B 7D 08 8B 4D 0C C1 E9 07 66 0F EF C0 EB 08 8D A4 24 00 00 00 00 90 66 0F 7F 07 66 0F 7F 47 10 66 0F 7F 47 20 66 0F 7F 47 30 66 0F 7F 47 40 66 0F 7F 47 50 66 0F 7F 47 60 66 0F 7F 47 70 8D BF 80 00 00 00 49 75 D0 8B 7D FC 8B E5 5D C3 55 8B EC }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_530
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "5.30"
		description = "with ZIP payload"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 2E 64 00 00 E9 78 FE FF FF 55 8B EC 83 EC 04 89 7D FC 8B 7D 08 8B 4D 0C C1 E9 07 66 0F EF C0 EB 08 8D A4 24 00 00 00 00 90 66 0F 7F 07 66 0F 7F 47 10 66 0F 7F 47 20 66 0F 7F 47 30 66 0F 7F 47 40 66 0F 7F 47 50 66 0F 7F 47 60 66 0F 7F 47 70 8D BF 80 00 00 00 49 75 D0 8B 7D FC 8B E5 5D C3 55 8B EC }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_531
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "5.31"
		description = "with ZIP payload"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 87 66 00 00 E9 78 FE FF FF 55 8B EC 83 EC 04 89 7D FC 8B 7D 08 8B 4D 0C C1 E9 07 66 0F EF C0 EB 08 8D A4 24 00 00 00 00 90 66 0F 7F 07 66 0F 7F 47 10 66 0F 7F 47 20 66 0F 7F 47 30 66 0F 7F 47 40 66 0F 7F 47 50 66 0F 7F 47 60 66 0F 7F 47 70 8D BF 80 00 00 00 49 75 D0 8B 7D FC 8B E5 5D C3 55 8B EC }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_540
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "5.40"
		description = "with ZIP payload"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 09 05 00 00 E9 80 FE FF FF 3B 0D A8 B0 42 00 F2 75 02 F2 C3 F2 E9 7E 06 00 00 E9 89 4C 00 00 55 8B EC 83 25 60 79 45 00 00 83 EC 2C 53 33 DB 43 09 1D AC B0 42 00 6A 0A E8 BD 1B 01 00 85 C0 0F 84 74 01 00 00 83 65 EC 00 33 C0 83 0D AC B0 42 00 02 33 C9 56 57 89 1D 60 79 45 00 8D 7D D4 53 0F A2 8B }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_550
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "5.50"
		description = "with ZIP payload"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 E6 04 00 00 E9 8E FE FF FF 3B 0D A8 D0 42 00 F2 75 02 F2 C3 F2 E9 5B 06 00 00 E9 E7 49 00 00 55 8B EC 83 25 88 CE 45 00 00 83 EC 28 53 33 DB 43 09 1D AC D0 42 00 6A 0A E8 4B 19 01 00 85 C0 0F 84 6D 01 00 00 83 65 F0 00 33 C0 83 0D AC D0 42 00 02 33 C9 56 57 89 1D 88 CE 45 00 8D 7D D8 53 0F A2 8B }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_35x
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "3.5x"
		description = "console version"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 33 FC 00 00 C3 00 00 00 00 90 90 52 50 8B 44 24 10 F7 24 24 8B C8 8B 44 24 04 F7 64 24 0C 03 C8 8B 04 24 F7 64 24 0C 03 D1 59 59 C2 08 00 55 53 56 57 33 FF 8B 5C 24 14 8B 4C 24 18 0B C9 75 14 90 90 90 90 0B D2 74 7C 90 90 90 90 0B DB 74 74 90 90 90 90 0B D2 79 0E 90 90 90 90 F7 DA F7 D8 83 DA 00 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_36x
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "3.6x"
		description = "console version"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 63 03 01 00 C3 00 00 00 00 90 90 52 50 8B 44 24 10 F7 24 24 8B C8 8B 44 24 04 F7 64 24 0C 03 C8 8B 04 24 F7 64 24 0C 03 D1 59 59 C2 08 00 55 53 56 57 33 FF 8B 5C 24 14 8B 4C 24 18 0B C9 75 14 90 90 90 90 0B D2 74 7C 90 90 90 90 0B DB 74 74 90 90 90 90 0B D2 79 0E 90 90 90 90 F7 DA F7 D8 83 DA 00 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_370
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "3.70"
		description = "console version"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 EB 06 01 00 C3 00 00 00 00 90 90 52 50 8B 44 24 10 F7 24 24 8B C8 8B 44 24 04 F7 64 24 0C 03 C8 8B 04 24 F7 64 24 0C 03 D1 59 59 C2 08 00 55 53 56 57 33 FF 8B 5C 24 14 8B 4C 24 18 0B C9 75 14 90 90 90 90 0B D2 74 7C 90 90 90 90 0B DB 74 74 90 90 90 90 0B D2 79 0E 90 90 90 90 F7 DA F7 D8 83 DA 00 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_371
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "3.71"
		description = "console version"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 53 09 01 00 C3 00 00 00 00 90 90 52 50 8B 44 24 10 F7 24 24 8B C8 8B 44 24 04 F7 64 24 0C 03 C8 8B 04 24 F7 64 24 0C 03 D1 59 59 C2 08 00 55 53 56 57 33 FF 8B 5C 24 14 8B 4C 24 18 0B C9 75 14 90 90 90 90 0B D2 74 7C 90 90 90 90 0B DB 74 74 90 90 90 90 0B D2 79 0E 90 90 90 90 F7 DA F7 D8 83 DA 00 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_380
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "3.80"
		description = "console version"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 AB 0B 01 00 C3 00 00 00 00 90 90 52 50 8B 44 24 10 F7 24 24 8B C8 8B 44 24 04 F7 64 24 0C 03 C8 8B 04 24 F7 64 24 0C 03 D1 59 59 C2 08 00 55 53 56 57 33 FF 8B 5C 24 14 8B 4C 24 18 0B C9 75 14 90 90 90 90 0B D2 74 7C 90 90 90 90 0B DB 74 74 90 90 90 90 0B D2 79 0E 90 90 90 90 F7 DA F7 D8 83 DA 00 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_391
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "3.91"
		description = "console version"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 51 C7 45 FC D9 F2 40 00 E8 2F FF FF FF 8D 45 FC 50 6A 01 E8 AE D4 FF FF 59 59 C9 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 95 AD FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 7E B2 FF FF C3 55 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_392
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "3.92"
		description = "console version"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 51 C7 45 FC D9 F2 40 00 E8 2F FF FF FF 8D 45 FC 50 6A 01 E8 AE D4 FF FF 59 59 C9 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 A4 AD FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 8D B2 FF FF C3 55 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_393
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "3.93"
		description = "console version"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 51 C7 45 FC D9 F2 40 00 E8 2F FF FF FF 8D 45 FC 50 6A 01 E8 AE D4 FF FF 59 59 C9 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 7E AD FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 67 B2 FF FF C3 55 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_400
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "4.00"
		description = "console version"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 51 C7 45 FC 41 03 41 00 E8 2F FF FF FF 8D 45 FC 50 6A 01 E8 40 D1 FF FF 59 59 C9 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 C5 A6 FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 F8 AB FF FF C3 55 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_401
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "4.01"
		description = "console version"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 51 C7 45 FC 41 03 41 00 E8 2F FF FF FF 8D 45 FC 50 6A 01 E8 3E D1 FF FF 59 59 C9 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 C3 A6 FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 F6 AB FF FF C3 55 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_411
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "4.11"
		description = "console version"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 51 C7 45 FC 41 03 41 00 E8 2F FF FF FF 8D 45 FC 50 6A 01 E8 8C D0 FF FF 59 59 C9 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 9B A5 FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 CE AA FF FF C3 55 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_420
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "4.20"
		description = "console version"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 51 C7 45 FC 55 13 41 00 E8 2F FF FF FF 8D 45 FC 50 6A 01 E8 8A D0 FF FF 59 59 C9 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 2A A4 FF FF 89 46 08 89 56 0C 8B 87 24 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 24 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 B3 A9 FF FF C3 56 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_501
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "5.01"
		description = "console version"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 AE 61 00 00 E9 A4 FE FF FF 8B FF 55 8B EC 56 8D 45 08 50 8B F1 E8 31 FD FF FF C7 06 A4 5F 42 00 8B C6 5E 5D C2 04 00 C7 01 A4 5F 42 00 E9 E6 FD FF FF 8B FF 55 8B EC 56 8B F1 C7 06 A4 5F 42 00 E8 D3 FD FF FF F6 45 08 01 74 07 56 E8 15 C1 FF FF 59 8B C6 5E 5D C2 04 00 8B FF 55 8B EC 56 57 8B 7D 08 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_510
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "5.10"
		description = "console version"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 8F 62 00 00 E9 A4 FE FF FF 8B FF 55 8B EC 56 8D 45 08 50 8B F1 E8 29 FD FF FF C7 06 B4 5F 42 00 8B C6 5E 5D C2 04 00 C7 01 B4 5F 42 00 E9 DE FD FF FF 8B FF 55 8B EC 56 8B F1 C7 06 B4 5F 42 00 E8 CB FD FF FF F6 45 08 01 74 07 56 E8 51 C1 FF FF 59 8B C6 5E 5D C2 04 00 8B FF 55 8B EC 56 57 8B 7D 08 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_511
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "5.11"
		description = "console version"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 8F 62 00 00 E9 A4 FE FF FF 8B FF 55 8B EC 56 8D 45 08 50 8B F1 E8 29 FD FF FF C7 06 C4 5F 42 00 8B C6 5E 5D C2 04 00 C7 01 C4 5F 42 00 E9 DE FD FF FF 8B FF 55 8B EC 56 8B F1 C7 06 C4 5F 42 00 E8 CB FD FF FF F6 45 08 01 74 07 56 E8 4D C1 FF FF 59 8B C6 5E 5D C2 04 00 8B FF 55 8B EC 56 57 8B 7D 08 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_520
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "5.20"
		description = "console version"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 B1 61 00 00 E9 A4 FE FF FF 8B FF 55 8B EC 56 8D 45 08 50 8B F1 E8 31 FD FF FF C7 06 C4 5F 42 00 8B C6 5E 5D C2 04 00 C7 01 C4 5F 42 00 E9 E6 FD FF FF 8B FF 55 8B EC 56 8B F1 C7 06 C4 5F 42 00 E8 D3 FD FF FF F6 45 08 01 74 07 56 E8 1D C2 FF FF 59 8B C6 5E 5D C2 04 00 8B FF 55 8B EC 56 57 8B 7D 08 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_521
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "5.21"
		description = "console version"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 B1 61 00 00 E9 A4 FE FF FF 8B FF 55 8B EC 56 8D 45 08 50 8B F1 E8 31 FD FF FF C7 06 C4 5F 42 00 8B C6 5E 5D C2 04 00 C7 01 C4 5F 42 00 E9 E6 FD FF FF 8B FF 55 8B EC 56 8B F1 C7 06 C4 5F 42 00 E8 D3 FD FF FF F6 45 08 01 74 07 56 E8 19 C2 FF FF 59 8B C6 5E 5D C2 04 00 8B FF 55 8B EC 56 57 8B 7D 08 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_530
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "5.30"
		description = "console version"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 B1 61 00 00 E9 A4 FE FF FF 8B FF 55 8B EC 56 8D 45 08 50 8B F1 E8 31 FD FF FF C7 06 88 5F 42 00 8B C6 5E 5D C2 04 00 C7 01 88 5F 42 00 E9 E6 FD FF FF 8B FF 55 8B EC 56 8B F1 C7 06 88 5F 42 00 E8 D3 FD FF FF F6 45 08 01 74 07 56 E8 21 C2 FF FF 59 8B C6 5E 5D C2 04 00 8B FF 55 8B EC 56 57 8B 7D 08 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_531
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "5.31"
		description = "console version"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 0B 64 00 00 E9 A4 FE FF FF 8B FF 55 8B EC 56 8D 45 08 50 8B F1 E8 31 FD FF FF C7 06 34 66 42 00 8B C6 5E 5D C2 04 00 C7 01 34 66 42 00 E9 E6 FD FF FF 8B FF 55 8B EC 56 8B F1 C7 06 34 66 42 00 E8 D3 FD FF FF F6 45 08 01 74 07 56 E8 FD C1 FF FF 59 8B C6 5E 5D C2 04 00 8B FF 55 8B EC 56 57 8B 7D 08 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_540
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "5.40"
		description = "console version"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 B0 04 00 00 E9 7A FE FF FF 3B 0D A4 71 43 00 F2 75 02 F2 C3 F2 E9 25 06 00 00 83 61 04 00 8B C1 83 61 08 00 C7 41 04 74 F5 42 00 C7 01 94 F6 42 00 C3 55 8B EC 56 FF 75 08 8B F1 E8 3F 81 FF FF C7 06 A0 F6 42 00 8B C6 5E 5D C2 04 00 83 61 04 00 8B C1 83 61 08 00 C7 41 04 A8 F6 42 00 C7 01 A0 F6 42 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_550
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WinRAR SFX"
		version = "5.50"
		description = "console version"
		source = "Made by Retdec Team"
	strings:
		$1 = { E8 94 04 00 00 E9 87 FE FF FF 3B 0D A4 71 43 00 F2 75 02 F2 C3 F2 E9 0A 06 00 00 83 61 04 00 8B C1 83 61 08 00 C7 41 04 74 F5 42 00 C7 01 9C F6 42 00 C3 55 8B EC 56 FF 75 08 8B F1 E8 D8 82 FF FF C7 06 A8 F6 42 00 8B C6 5E 5D C2 04 00 83 61 04 00 8B C1 83 61 08 00 C7 41 04 B0 F6 42 00 C7 01 A8 F6 42 }
	condition:
		$1 at pe.entry_point
}

rule wix_toolset_36
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WiX Toolset"
		version = "3.6"
		source = "Made by RetDec Team"
	strings:
		$1 = { E8 AC 14 00 00 E9 79 FE FF FF 8B FF 55 8B EC 8B 45 08 8B 00 81 38 63 73 6D E0 75 2A 83 78 10 03 75 24 8B 40 14 3D 20 05 93 19 74 15 3D 21 05 93 19 74 0E 3D 22 05 93 19 74 07 3D 00 40 99 01 75 05 E8 01 15 00 00 33 C0 5D C2 04 00 68 55 47 40 00 FF 15 7C 11 40 00 33 C0 C3 8B FF 55 8B EC 57 BF E8 03 00 }
	condition:
		$1 at pe.entry_point
}

rule wix_toolset_37
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WiX Toolset"
		version = "3.7"
		source = "Made by RetDec Team"
	strings:
		$1 = { E8 1E 1F 00 00 E9 89 FE FF FF CC CC CC CC CC CC CC CC CC CC 8B 54 24 0C 8B 4C 24 04 85 D2 74 69 33 C0 8A 44 24 08 84 C0 75 16 81 FA 80 00 00 00 72 0E 83 3D E8 3E 45 00 00 74 05 E9 7E 1F 00 00 57 8B F9 83 FA 04 72 31 F7 D9 83 E1 03 74 0C 2B D1 88 07 83 C7 01 83 E9 01 75 F6 8B C8 C1 E0 08 03 C1 8B C8 }
	condition:
		$1 at pe.entry_point
}

rule wix_toolset_38
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WiX Toolset"
		version = "3.8"
		source = "Made by RetDec Team"
	strings:
		$1 = { E8 C9 39 00 00 E9 7F FE FF FF 3B 0D D0 60 45 00 75 02 F3 C3 E9 C4 40 00 00 CC CC 8B 54 24 0C 8B 4C 24 04 85 D2 74 7F 0F B6 44 24 08 0F BA 25 44 7C 45 00 01 73 0D 8B 4C 24 0C 57 8B 7C 24 08 F3 AA EB 5D 8B 54 24 0C 81 FA 80 00 00 00 7C 0E 0F BA 25 80 61 45 00 01 0F 82 79 41 00 00 57 8B F9 83 FA 04 72 }
	condition:
		$1 at pe.entry_point
}

rule wix_toolset_39
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WiX Toolset"
		version = "3.9"
		source = "Made by RetDec Team"
	strings:
		$1 = { E8 FC 39 00 00 E9 7F FE FF FF 3B 0D 00 20 46 00 75 02 F3 C3 E9 85 41 00 00 CC CC CC CC 8B 54 24 0C 8B 4C 24 04 85 D2 74 7F 0F B6 44 24 08 0F BA 25 5C 3F 46 00 01 73 0D 8B 4C 24 0C 57 8B 7C 24 08 F3 AA EB 5D 8B 54 24 0C 81 FA 80 00 00 00 7C 0E 0F BA 25 60 20 46 00 01 0F 82 3A 42 00 00 57 8B F9 83 FA }
	condition:
		$1 at pe.entry_point
}

rule wix_toolset_39r2
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WiX Toolset"
		version = "3.9r2"
		source = "Made by RetDec Team"
	strings:
		$1 = { E8 00 3A 00 00 E9 7F FE FF FF 3B 0D 00 20 46 00 75 02 F3 C3 E9 89 41 00 00 CC CC CC CC CC CC CC CC 8B 54 24 0C 8B 4C 24 04 85 D2 74 7F 0F B6 44 24 08 0F BA 25 5C 3F 46 00 01 73 0D 8B 4C 24 0C 57 8B 7C 24 08 F3 AA EB 5D 8B 54 24 0C 81 FA 80 00 00 00 7C 0E 0F BA 25 60 20 46 00 01 0F 82 3A 42 00 00 57 }
	condition:
		$1 at pe.entry_point
}

rule wix_toolset_310
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WiX Toolset"
		version = "3.10"
		source = "Made by RetDec Team"
	strings:
		$1 = { E8 95 03 00 00 E9 80 FE FF FF 3B 0D 04 90 46 00 F2 75 02 F2 C3 F2 E9 1F 07 00 00 55 8B EC EB 1F FF 75 08 E8 AD 6C 00 00 59 85 C0 75 12 83 7D 08 FF 75 07 E8 F6 08 00 00 EB 05 E8 D2 08 00 00 FF 75 08 E8 24 6D 00 00 59 85 C0 74 D4 5D C3 55 8B EC FF 75 08 E8 FF 08 00 00 59 5D C3 55 8B EC F6 45 08 01 56 }
	condition:
		$1 at pe.entry_point
}

rule wix_toolset_3101
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WiX Toolset"
		version = "3.10.1"
		source = "Made by RetDec Team"
	strings:
		$1 = { E8 91 03 00 00 E9 80 FE FF FF 3B 0D 04 90 46 00 F2 75 02 F2 C3 F2 E9 5B 07 00 00 55 8B EC EB 1F FF 75 08 E8 C5 6C 00 00 59 85 C0 75 12 83 7D 08 FF 75 07 E8 32 09 00 00 EB 05 E8 0E 09 00 00 FF 75 08 E8 3C 6D 00 00 59 85 C0 74 D4 5D C3 55 8B EC FF 75 08 E8 3B 09 00 00 59 5D C3 55 8B EC F6 45 08 01 56 }
	condition:
		$1 at pe.entry_point
}

rule wix_toolset_3102
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WiX Toolset"
		version = "3.10.2"
		source = "Made by RetDec Team"
	strings:
		$1 = { E8 A3 04 00 00 E9 80 FE FF FF CC CC CC CC CC CC CC CC 8B 44 24 08 8B 4C 24 10 0B C8 8B 4C 24 0C 75 09 8B 44 24 04 F7 E1 C2 10 00 53 F7 E1 8B D8 8B 44 24 08 F7 64 24 14 03 D8 8B 44 24 08 F7 E1 03 D3 5B C2 10 00 55 8B EC EB 1F FF 75 08 E8 6B 6C 00 00 59 85 C0 75 12 83 7D 08 FF 75 07 E8 B3 08 00 00 EB }
	condition:
		$1 at pe.entry_point
}

rule wix_toolset_3103
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WiX Toolset"
		version = "3.10.3"
		source = "Made by RetDec Team"
	strings:
		$1 = { E8 C4 04 00 00 E9 80 FE FF FF CC CC CC CC CC CC CC CC CC CC CC CC 8B 44 24 08 8B 4C 24 10 0B C8 8B 4C 24 0C 75 09 8B 44 24 04 F7 E1 C2 10 00 53 F7 E1 8B D8 8B 44 24 08 F7 64 24 14 03 D8 8B 44 24 08 F7 E1 03 D3 5B C2 10 00 55 8B EC EB 1F FF 75 08 E8 7D 6C 00 00 59 85 C0 75 12 83 7D 08 FF 75 07 E8 13 }
	condition:
		$1 at pe.entry_point
}

rule wix_toolset_311
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "WiX Toolset"
		version = "3.11"
		source = "Made by RetDec Team"
	strings:
		$1 = { E8 01 05 00 00 E9 8E FE FF FF CC CC CC CC CC CC CC CC CC 8B 44 24 08 8B 4C 24 10 0B C8 8B 4C 24 0C 75 09 8B 44 24 04 F7 E1 C2 10 00 53 F7 E1 8B D8 8B 44 24 08 F7 64 24 14 03 D8 8B 44 24 08 F7 E1 03 D3 5B C2 10 00 CC CC CC CC CC CC CC CC CC CC CC CC 80 F9 40 73 15 80 F9 20 73 06 0F AD D0 D3 EA C3 8B }
	condition:
		$1 at pe.entry_point
}

rule xt_app_launcher
{
	meta:
        author = "RetDec Team"
		category = "installer"
		name = "Xenocode Application Launcher"
		source = "Made by RetDec Team"
	strings:
		$h00 = { 8b 4f 3c 03 cf 0f b7 51 14 56 8d 74 0a 18 0f b7 51 06 33 c0 85 d2 76 16 8d 4e 10 8b 31 85 f6 74 07 8b 41 04 03 c6 03 c7 83 c1 28 4a 75 ed 2b c7 5e c3 }
		$h01 = { 55 8b ec 51 8b 4f 3c 03 cf 0f b7 51 14 53 0f b7 59 06 33 c0 8d 54 0a 18 89 45 fc 3b d8 76 29 83 c2 14 56 8b 72 fc 85 f6 74 12 8b 0a 8d 04 0e 83 e1 11 }
	condition:
		pe.number_of_sections == 6 and
		pe.sections[2].name == ".xcpad" and
		pe.overlay.size != 0 and
		any of them
}
