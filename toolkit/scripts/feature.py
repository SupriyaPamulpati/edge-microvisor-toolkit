#!/usr/bin/env python3
"""
Intel Security Features Checker
Checks availability and status of various Intel security and virtualization features
"""

import subprocess
import re
import os
import sys
from pathlib import Path
from typing import Dict, Tuple, Optional, List

class IntelFeatureChecker:
    def __init__(self):
        self.cpu_info = self.get_cpu_info()

    def get_cpu_info(self) -> Dict[str, str]:
        """Get CPU information including CPUID"""
        cpu_info = {}
        try:
            with open('/proc/cpuinfo', 'r') as f:
                content = f.read()

            # Extract CPU model name
            model_match = re.search(r'model name\s*:\s*(.+)', content)
            if model_match:
                cpu_info['model_name'] = model_match.group(1).strip()

            # Extract CPU family, model, stepping for CPUID
            family_match = re.search(r'cpu family\s*:\s*(\d+)', content)
            model_num_match = re.search(r'^model\s*:\s*(\d+)', content, re.MULTILINE)
            stepping_match = re.search(r'stepping\s*:\s*(\d+)', content)

            if family_match and model_num_match and stepping_match:
                family = int(family_match.group(1))
                model = int(model_num_match.group(1))
                stepping = int(stepping_match.group(1))
                cpu_info['cpuid'] = f"Family: {family}, Model: {model}, Stepping: {stepping}"
                cpu_info['cpuid_hex'] = f"Family: 0x{family:x}, Model: 0x{model:x}, Stepping: 0x{stepping:x}"

            # Extract vendor ID
            vendor_match = re.search(r'vendor_id\s*:\s*(.+)', content)
            if vendor_match:
                cpu_info['vendor_id'] = vendor_match.group(1).strip()

        except Exception as e:
            cpu_info['error'] = str(e)

        return cpu_info

    def run_command(self, cmd: str) -> str:
        """Execute shell command and return output"""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.stdout.strip()
        except Exception:
            return ""

    def check_cpuid_flags(self) -> Dict[str, bool]:
        """Check CPU flags from /proc/cpuinfo"""
        flags = {}
        try:
            with open('/proc/cpuinfo', 'r') as f:
                content = f.read()
                if 'flags' in content:
                    flag_line = re.search(r'flags\s*:\s*(.+)', content)
                    if flag_line:
                        cpu_flags = flag_line.group(1).split()
                        flags = {flag: True for flag in cpu_flags}
        except Exception:
            pass
        return flags

    def check_device_identity(self) -> List[Tuple[str, bool, bool]]:
        """Check Device Identity features"""
        cpu_flags = self.check_cpuid_flags()
        features = []

        # RDRAND
        rdrand_available = 'rdrand' in cpu_flags
        features.append(("RDRAND", rdrand_available, rdrand_available))

        # RDSEED
        rdseed_available = 'rdseed' in cpu_flags
        features.append(("RDSEED", rdseed_available, rdseed_available))

        # System UUID
        uuid_output = self.run_command("sudo dmidecode -s system-uuid 2>/dev/null")
        uuid_available = bool(uuid_output and uuid_output != "Not Settable")
        features.append(("System UUID", uuid_available, uuid_available))

        # Intel ME/AMT
        mei_devices = self.run_command("lspci | grep -i 'management engine\\|mei'")
        mei_available = bool(mei_devices)
        features.append(("Intel ME", mei_available, mei_available))

        return features

    def check_crypto_acceleration(self) -> List[Tuple[str, bool, bool]]:
        """Check Intel Crypto Acceleration"""
        cpu_flags = self.check_cpuid_flags()
        features = []

        # AES-NI
        aes_available = 'aes' in cpu_flags
        features.append(("AES-NI", aes_available, aes_available))

        # SHA-NI
        sha_available = 'sha_ni' in cpu_flags
        features.append(("SHA-NI", sha_available, sha_available))

        # PCLMULQDQ
        pclmul_available = 'pclmulqdq' in cpu_flags
        features.append(("PCLMULQDQ", pclmul_available, pclmul_available))

        return features

    def check_tme(self) -> List[Tuple[str, bool, bool]]:
        """Check Total Memory Encryption"""
        cpu_flags = self.check_cpuid_flags()
        features = []

        # TME only (removed MKTME as requested)
        tme_available = 'tme' in cpu_flags
        tme_enabled = False
        if tme_available:
            tme_dmesg = self.run_command("dmesg | grep -i 'tme.*enabled'")
            tme_enabled = bool(tme_dmesg)
        features.append(("TME", tme_available, tme_enabled))

        return features

    def check_mbec(self) -> List[Tuple[str, bool, bool]]:
        """Check MBEC (Mode-Based Execution Control) support"""
        features = []
        
        mbec_available = False
        mbec_enabled = False
        
        # Check MSR 0x48B (IA32_VMX_PROCBASED_CTLS2) for MBEC support
        # This MSR contains the secondary processor-based VM-execution controls
        # Bit 54 specifically indicates MBEC (Mode-Based Execution Control) support
        msr_result = self.run_command("sudo rdmsr 0x48B 2>/dev/null")
        
        if msr_result:
            try:
                msr_value = int(msr_result.strip(), 16)
                # Check bit 54 for MBEC support using hex notation to avoid overflow
                # Bit 54 = 0x40000000000000 indicates native hardware MBEC support
                mbec_available = (msr_value & 0x40000000000000) != 0
                
                # If MBEC is available, check if it's enabled
                # MBEC is considered enabled if the hardware supports it and VT-x is enabled
                if mbec_available:
                    # Check if /dev/kvm exists as a proxy for virtualization being enabled
                    mbec_enabled = Path("/dev/kvm").exists()
            except (ValueError, TypeError):
                mbec_available = False
                mbec_enabled = False
        
        features.append(("MBEC", mbec_available, mbec_enabled))
        return features

    def check_virtualization(self) -> List[Tuple[str, bool, bool]]:
        """Check Intel Virtualization"""
        cpu_flags = self.check_cpuid_flags()
        features = []

        # VT-x (VMX)
        vtx_available = False
        vtx_enabled = False

        msr_result = self.run_command("sudo rdmsr 0x3A 2>/dev/null")

        if msr_result:
            try:
                msr_value = int(msr_result.strip(), 16)

                # Check if VT-x is supported by examining bit 0 of MSR 0x3A
                # Bit 0 = 1 means VT-x feature is available
                vtx_available = (msr_value & 0x1) == 1

                if vtx_available:
                    # Check if VT-x is enabled
                    # Bit 2 (0x4) in MSR 0x3A indicates if VT-x is locked
                    vtx_locked = (msr_value & 0x4) != 0
                    kvm_check = Path("/dev/kvm").exists()

                    vtx_enabled = (not vtx_locked) or kvm_check

            except (ValueError, TypeError):
                vtx_available = False
                vtx_enabled = False

        features.append(("VT-x", vtx_available, vtx_enabled))

        # VT-d
        vtd_available = False
        vtd_enabled = False
        vtd_dmesg = self.run_command("sudo dmesg | grep -i 'iommu'")
        if vtd_dmesg:
            vtd_available = True
            # Check if IOMMU is enabled in the kernel messages
            vtd_enabled = any(keyword in vtd_dmesg.lower() for keyword in [
                "iommu enabled",
                "iommu: enabled",
                "intel-iommu: enabled",
                "dmar: iommu enabled"
            ])
        features.append(("VT-d (IOMMU)", vtd_available, vtd_enabled))
        
        # Add MBEC check
        mbec_features = self.check_mbec()
        features.extend(mbec_features)
        
        return features

    def check_secure_boot_guard(self) -> List[Tuple[str, bool, bool]]:
        """Check Secure Boot and Boot Guard"""
        features = []

        # Secure Boot
        sb_available = False
        sb_enabled = False
        sb_output = self.run_command("mokutil --sb-state 2>/dev/null")
        if "SecureBoot enabled" in sb_output:
            sb_available = True
            sb_enabled = True
        elif "SecureBoot disabled" in sb_output:
            sb_available = True
            sb_enabled = False
        else:
            # Alternative check
            efi_check = self.run_command("efivar -n 8be4df61-93ca-11d2-aa0d-00e098032b8c-SecureBoot 2>/dev/null")
            if efi_check:
                sb_available = True
                sb_enabled = "01 00 00 00 01" in efi_check
        features.append(("Secure Boot", sb_available, sb_enabled))

        # Boot Guard (SMX)
        cpu_flags = self.check_cpuid_flags()
        smx_available = 'smx' in cpu_flags
        smx_enabled = False
        if smx_available:
            bg_dmesg = self.run_command("dmesg | grep -i 'boot.*guard'")
            smx_enabled = bool(bg_dmesg)
        features.append(("Boot Guard (SMX)", smx_available, smx_enabled))

        return features

    def check_tpm(self) -> List[Tuple[str, bool, bool]]:
        """Check TPM"""
        features = []

        # TPM Device
        tpm_device = Path("/dev/tpm0").exists() or Path("/dev/tpmrm0").exists()
        tpm_version = ""
        tpm_available = False
        tpm_enabled = False

        if tpm_device:
            tpm_version = self.run_command("cat /sys/class/tpm/tpm0/tpm_version_major 2>/dev/null")
            tpm_available = True
            tpm_enabled = True
        else:
            # Check dmesg for TPM
            tpm_dmesg = self.run_command("dmesg | grep -i tpm")
            if tpm_dmesg:
                tpm_available = True
                tpm_enabled = "enabled" in tpm_dmesg.lower() and "disabled" not in tpm_dmesg.lower()
                if "2.0" in tpm_dmesg:
                    tpm_version = "2"

        if tpm_version == "2":
            features.append(("TPM 2.0", tpm_available, tpm_enabled))
        elif tpm_version == "1":
            features.append(("TPM 1.2", tpm_available, tpm_enabled))
        else:
            features.append(("TPM", tpm_available, tpm_enabled))

        return features

    def check_fde(self) -> List[Tuple[str, bool, bool]]:
        """Check Full Disk Encryption"""
        features = []

        # LUKS
        luks_devices = self.run_command("lsblk -f | grep crypto_LUKS")
        luks_available = bool(luks_devices)
        features.append(("LUKS", luks_available, luks_available))

        # dm-crypt
        dmcrypt = self.run_command("lsmod | grep dm_crypt")
        dmcrypt_available = bool(dmcrypt)
        features.append(("dm-crypt", dmcrypt_available, dmcrypt_available))

        # cryptsetup
        cryptsetup = self.run_command("which cryptsetup 2>/dev/null")
        cryptsetup_available = bool(cryptsetup)
        features.append(("cryptsetup", cryptsetup_available, cryptsetup_available))

        return features

    def check_txt(self) -> List[Tuple[str, bool, bool]]:
        """Check Intel TXT"""
        cpu_flags = self.check_cpuid_flags()
        features = []

        # VMX
        vmx_available = 'vmx' in cpu_flags
        vmx_enabled = Path("/dev/kvm").exists()
        features.append(("VMX", vmx_available, vmx_enabled))

        # SMX
        smx_available = 'smx' in cpu_flags
        # Check if SMX is actually enabled via dmesg or TXT-related messages
        smx_enabled = False
        if smx_available:
            smx_dmesg = self.run_command("dmesg | grep -i 'smx\\|txt'")
            smx_enabled = bool(smx_dmesg and 'enabled' in smx_dmesg.lower())
        features.append(("SMX", smx_available, smx_enabled))

        # TXT Capability
        txt_capable = vmx_available and smx_available
        txt_enabled = False
        if txt_capable:
            txt_dmesg = self.run_command("dmesg | grep -i 'txt.*enabled'")
            tboot_check = self.run_command("which tboot 2>/dev/null")
            txt_enabled = bool(txt_dmesg) or bool(tboot_check)
        features.append(("TXT Capable", txt_capable, txt_enabled))

        return features

    def check_ibecc(self) -> List[Tuple[str, bool, bool]]:
        """Check In-Band ECC"""
        features = []

        # EDAC
        edac_devices = self.run_command("ls /sys/devices/system/edac/mc/ 2>/dev/null")
        edac_available = bool(edac_devices)
        features.append(("EDAC", edac_available, edac_available))

        # IBECC
        ibecc_dmesg = self.run_command("dmesg | grep -i ibecc")
        ibecc_available = bool(ibecc_dmesg)
        ibecc_enabled = False
        if ibecc_available:
            ibecc_enabled = "enabled" in ibecc_dmesg.lower()
        features.append(("IBECC", ibecc_available, ibecc_enabled))

        # ECC Memory
        ecc_check = self.run_command("dmesg | grep -i 'ecc.*enabled'")
        ecc_available = bool(ecc_check)
        features.append(("ECC Memory", ecc_available, ecc_available))

        return features

    def check_sgx(self) -> List[Tuple[str, bool, bool]]:
        """Check for Intel SGX"""
        features = []
        cpu_flags = self.check_cpuid_flags()

        # Check CPU flag first
        sgx_available = 'sgx' in cpu_flags
        sgx_enabled = False

        if sgx_available:
            # If CPU supports it, check if it's enabled in the kernel/BIOS
            sgx_dmesg = self.run_command("dmesg | grep -i sgx")
            sgx_dev = self.run_command("ls /dev | grep -i sgx")
            if "enabled" in sgx_dmesg.lower() or sgx_dev:
                sgx_enabled = True

        features.append(("Intel SGX", sgx_available, sgx_enabled))
        return features

    def print_cpu_info(self):
        """Print CPU information including CPUID"""
        print("CPU Information")
        print("=" * 80)
        print(f"Model Name: {self.cpu_info.get('model_name', 'Unknown')}")
        print(f"Vendor ID:  {self.cpu_info.get('vendor_id', 'Unknown')}")
        print(f"CPUID:      {self.cpu_info.get('cpuid', 'Unknown')}")
        print(f"CPUID (Hex): {self.cpu_info.get('cpuid_hex', 'Unknown')}")
        print()

    def check_all_features(self):
        """Check all features and return results"""
        feature_checks = [
            ("Device Identity", self.check_device_identity),
            ("Intel Crypto Acceleration", self.check_crypto_acceleration),
            ("TME (Total Memory Encryption)", self.check_tme),
            ("Intel Virtualization", self.check_virtualization),
            ("TPM", self.check_tpm),
            ("FDE (Full Disk Encryption)", self.check_fde),
            ("IBECC (In-Band ECC)", self.check_ibecc),
            # TSE-related features grouped at the bottom
            ("Secure Boot/Boot Guard", self.check_secure_boot_guard),
            ("TXT (Trusted Execution)", self.check_txt),
            ("Intel SGX", self.check_sgx),
        ]

        all_features = []
        for category_name, check_func in feature_checks:
            try:
                platform_features = check_func()
                for feature_name, available, enabled in platform_features:
                    all_features.append((category_name, feature_name, available, enabled))
            except Exception as e:
                all_features.append((category_name, "Error", False, False))

        return all_features

    def print_results_table(self, results):
        """
        Calculates TSE status, adds it to the results, and prints everything
        in a proper table format with TSE features grouped together.
        """
        # --- Calculate TSE Status ---
        feature_status = {name: enabled for _, name, available, enabled in results if available}
        boot_guard_ok = feature_status.get("Boot Guard (SMX)", False)
        txt_ok = feature_status.get("TXT Capable", False)
        sgx_ok = feature_status.get("Intel SGX", False)
        tse_enabled = boot_guard_ok and txt_ok and sgx_ok

        print("Intel Security Features Status")
        print("=" * 100)

        # Table header
        print(f"{'Security Features':<30} {'Platform Support':<25} {'Available':<15} {'Enabled/Disabled'}")
        print("-" * 100)

        current_category = ""
        for category, feature_name, available, enabled in results:
            # Format availability
            available_str = "✓ YES" if available else "✗ NO"
            available_color = "\033[92m" if available else "\033[91m"

            # Format enabled/disabled
            if available:
                enabled_str = "✓ ENABLED" if enabled else "✗ DISABLED"
                enabled_color = "\033[92m" if enabled else "\033[93m"
            else:
                enabled_str = "N/A"
                enabled_color = "\033[90m"

            reset = "\033[0m"

            # Show category name only for the first feature in each category
            if category != current_category:
                category_display = category
                current_category = category
            else:
                category_display = ""

            # Add tab space separation as requested
            feature_display = f"\t{feature_name}"

            print(f"{category_display:<30} {feature_display:<25} {available_color}{available_str:<15}{reset} {enabled_color}{enabled_str}{reset}")

        # Add TSE summary section
        print("-" * 100)
        print("TSE (Trusted Secure Execution) Summary")
        print("-" * 100)

        # TSE component status
        tse_components = [
            ("Boot Guard", boot_guard_ok),
            ("TXT Capable", txt_ok),
            ("Intel SGX", sgx_ok)
        ]

        # Overall TSE status
        tse_status_str = "✓ ENABLED" if tse_enabled else "✗ DISABLED"
        tse_status_color = "\033[92m" if tse_enabled else "\033[91m"

        print("-" * 100)

        # Summary
        total_features = len(results)
        available_features = sum(1 for _, _, available, _ in results if available)
        enabled_features = sum(1 for _, _, available, enabled in results if available and enabled)

        print(f"\nSummary:")
        print(f"┌─────────────────────────┬─────────┐")
        print(f"│ Total Features          │ {total_features:>7} │")
        print(f"│ Available Features      │ {available_features:>7} │")
        print(f"│ Enabled Features        │ {enabled_features:>7} │")
        print(f"│ Disabled Features       │ {available_features - enabled_features:>7} │")
        print(f"└─────────────────────────┴─────────┘")

def main():
    if os.geteuid() != 0:
        print("Warning: Running without root privileges. Some checks may be limited.")
        print("For complete results, run with: sudo python3 feature.py\n")

    checker = IntelFeatureChecker()

    # Print CPU info first
    checker.print_cpu_info()

    # Check and print features
    results = checker.check_all_features()
    checker.print_results_table(results)

    print("\nNotes:")
    print("• Available: Feature is supported by the hardware")
    print("• Enabled: Feature is currently active/configured")
    print("• Some features may require BIOS/UEFI configuration")
    print("• Run with sudo for complete information")

if __name__ == "__main__":
    main()
