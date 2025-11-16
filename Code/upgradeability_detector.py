import argparse
import json
import csv
import requests
import subprocess 
from typing import List, Dict, Any, Optional

# --- REQUIRED LIBRARIES (ASSUMED INSTALLED) ---
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.style import Style
from web3 import Web3, HTTPProvider

# --- SLITHER DEPENDENCY IMPORTS ---
from slither.slither import Slither
from slither.core.declarations import Contract

# --- API KEYS ---
INFURA_URL = "https://eth-sepolia.g.alchemy.com/v2/fyo2b5k1kvj_cSctPtlurjb7H1MPikmm"
ETHERSCAN_API_KEY = "T5TZ6QEVWPV77NJF3FSRQGNE88M1335RAH"
EIP1967_IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382abe"
EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e82ee117efad97c026403063"
ZERO_ADDRESS_HEX = "0x" + "00" * 32

# Initialize the Web3 connection object
try:
    w3 = Web3(HTTPProvider(INFURA_URL)) 
    if hasattr(w3, "is_connected") and w3.is_connected():
        pass
    elif hasattr(w3, "isConnected") and w3.isConnected():
        pass
except Exception as e:
    print(f"FATAL ERROR during Web3 initialization: {e}")
    exit(1)


def etherscan_proxy_check(contract_address: str, console: Console) -> Optional[str]:
    BASE_URL = "https://api.etherscan.io/api"
    params = {
        'module': 'contract',
        'action': 'getsourcecode',
        'address': contract_address,
        'apikey': ETHERSCAN_API_KEY,
        'chainid': '11155111' 
    }

    try:
        response = requests.get(BASE_URL, params=params, timeout=10)
        response.raise_for_status() 
        data = response.json()
        
        if data.get('status') != '1' or not isinstance(data.get('result'), list) or len(data['result']) == 0:
            return None
            
        contract_data = data['result'][0]
        impl_address = contract_data.get('Implementation', contract_data.get('Proxy'))
        
        if impl_address and impl_address != ZERO_ADDRESS_HEX and impl_address != "":
            return impl_address

        return None 

    except requests.exceptions.RequestException:
        return None
    except Exception:
        return None


def slither_analyze(file_path: str) -> Dict[str, Any]:
    """
    Executes Static Analysis (Proxy, Admin, Delegatecall, CREATE2).
    """
    results = {
        "name": file_path,
        "upgrade_function_detected": False,
        "delegatecall_detected": False, 
        "admin_control": "None",
        "proxy_pattern": "Non-Upgradeable",
        "create2_detected": False,
        "staged_analysis": {
            "Compilation": "Failed",
            "Inheritance": "Not Detected",
            "Upgrade_Fn": "Not Found",
            "Access_Control": "None",
            "Low_Level_Calls": "Clean"
        }
    }

    try:
        # --- COMPILATION FIX REQUIRED ---
        # NOTE: Manually change pragma in all .sol files to match the stable version used below.
        slither = Slither(file_path, solc='0.8.30', solc_args="--allow-paths .")
        
        # If this line is reached, compilation was successful
        results["staged_analysis"]["Compilation"] = "Success"
        
        main_contract = get_main_contract(slither)
        if not main_contract:
            raise Exception("No main contract found after compilation.")
            
        # --- Detection Logic (2.2, 2.3, 2.4 are fully implemented below) ---
        inherited_names = [i.name for i in main_contract.inheritance]

        if 'UUPSUpgradeable' in inherited_names or 'EIP1967Proxy' in inherited_names:
            results['proxy_pattern'] = 'UUPS'
            results["staged_analysis"]["Inheritance"] = "UUPS Found"
        elif 'TransparentUpgradeableProxy' in inherited_names:
            results['proxy_pattern'] = 'Transparent'
            results["staged_analysis"]["Inheritance"] = "Transparent Found"
            
        for func in main_contract.functions:
            if func.full_name.startswith('upgradeTo('):
                results['upgrade_function_detected'] = True
                results["staged_analysis"]["Upgrade_Fn"] = "upgradeTo() Found"
                
                if not func.modifiers:
                    results['admin_control'] = 'None (Public)' 
                    results["staged_analysis"]["Access_Control"] = "UNPROTECTED!"
                else:
                    modifier_names = [m.name for m in func.modifiers]
                    
                    if 'onlyOwner' in modifier_names or 'onlyAdmin' in modifier_names or 'onlyRole' in modifier_names:
                        results['admin_control'] = ', '.join(modifier_names) 
                        results["staged_analysis"]["Access_Control"] = "Centralized"
                    else:
                         results['admin_control'] = 'Governance/Timelock'
                         results["staged_analysis"]["Access_Control"] = "Secure/Timelock"

                break 

        for function in main_contract.functions_and_modifiers:
            if any(call.name == "DELEGATECALL" for call in function.low_level_calls):
                 results['delegatecall_detected'] = True
                 results["staged_analysis"]["Low_Level_Calls"] = "DELEGATECALL detected"
                 break

        if any(f.contains_create2() for f in main_contract.functions):
            results['create2_detected'] = True
            if results['proxy_pattern'] == 'Non-Upgradeable':
                 results['proxy_pattern'] = 'CREATE2 Factory'
                 results["staged_analysis"]["Inheritance"] = "CREATE2 Factory"


    except Exception as e:
        # --- FIX #1: Preserve the file name even on compilation failure ---
        # This prevents the KeyError in the reporting functions
        results["name"] = file_path 
        results["proxy_pattern"] = f"Solc Compile Fail"
        results["admin_control"] = f"Solidity Error: {str(e)[:50]}..."
        results["staged_analysis"]["Compilation"] = f"Failed: {str(e).splitlines()[0][:30]}..."
        # NOTE: The print below is what displays the final error details in your console output.
        print(f"\n❌ Slither Compilation Error for {file_path}: Solidity compilation failed (Check imports/version).")
        print(f"Error Output: {e}")
    
    return results

def web3_get_storage_at(contract_address: str, slot: str) -> str:
    try:
        checksum_address = Web3.to_checksum_address(contract_address)
        slot_int = int(slot, 16)
        
        slot_data_bytes = w3.eth.get_storage_at(checksum_address, slot_int)
        return Web3.to_hex(slot_data_bytes) 
    
    except Exception:
        return ZERO_ADDRESS_HEX 

def get_main_contract(slither_instance: Slither) -> Optional[Contract]:
    """Tries to identify the main contract in a multi-file analysis."""
    if not slither_instance.contracts:
        return None
    return sorted(slither_instance.contracts, key=lambda c: len(c.name))[-1]

def delegatecall_detector(analysis_result: Dict[str, Any]) -> bool:
    return analysis_result.get("delegatecall_detected", False)

def proxy_detector(analysis_result: Dict[str, Any], contract_address: Optional[str] = None, console: Optional[Console] = None) -> Dict[str, Any]:
    # 1. Default for source analysis (-f argument)
    if contract_address is None:
        return {
            "pattern": analysis_result.get("proxy_pattern", "Non-Upgradeable"),
            "admin_control": analysis_result.get("admin_control", "None")
        }

    # 2. Deployed Address Analysis (-a argument logic)
    console = console or Console()
    
    # PRIORITY 1: Etherscan API Check 
    impl_address_etherscan = etherscan_proxy_check(contract_address, console)
    
    if impl_address_etherscan:
        return {
            "pattern": "Etherscan Verified Proxy", 
            "admin_control": "Centralized/Unknown"
        }

    # PRIORITY 2: EIP-1967 Slot Check (Web3 RPC)
    impl_address_web3 = web3_get_storage_at(contract_address, EIP1967_IMPLEMENTATION_SLOT)
    
    if impl_address_web3 != ZERO_ADDRESS_HEX:
        admin_address_web3 = web3_get_storage_at(contract_address, EIP1967_ADMIN_SLOT)
        
        if admin_address_web3 != ZERO_ADDRESS_HEX:
            return {"pattern": "Transparent Proxy (Slot Match)", "admin_control": "Centralized/Transparent"}
        else:
            return {"pattern": "UUPS/Beacon Proxy (Slot Match)", "admin_control": "Logic in Impl. Contract"}
    
    # 3. Default failure
    return {"pattern": "Non-Upgradeable", "admin_control": "None"}


def create2_detector(analysis_result: Dict[str, Any]) -> bool:
    return analysis_result.get("create2_detected", False)

def print_deployed_status(results_list: List[Dict[str, Any]], console: Console):
    """
    Prints the status of the proxy detection for DEPLOYED ADDRESSES only.
    This runs first to show the Web3/Etherscan check outcome.
    """
    
    deployed_results = [r for r in results_list if r["Address"] != "N/A (Source)"]
    if not deployed_results:
        return

    console.rule("[bold magenta]DEPLOYED ADDRESS ANALYSIS STATUS[/bold magenta]")

    for result in deployed_results:
        pattern = result["Upgradeability Pattern"]
        address = result["Address"]
        
        if "Verified Proxy" in pattern or "Slot Match" in pattern:
            status_text = f"✅ SUCCESS: Proxy Confirmed via {pattern.split('(')[0].strip()}"
            style = "bold green"
        elif pattern == "Non-Upgradeable":
            status_text = "❓ NOT FOUND: Contract is not an identified proxy"
            style = "bold yellow"
        else:
             # Default failure due to API/Web3 not finding an address
             status_text = "⚠️ CHECK FAILURE: Etherscan/Web3 call failed or returned no data."
             style = "bold red"
             
        console.print(f"Address: [cyan]{address}[/cyan]")
        console.print(f"Status: {status_text}", style=style)
        console.print(f"Pattern Detected: {pattern}\n", style="dim")


def print_staged_results(results_list: List[Dict[str, Any]], console: Console):
    """Prints a detailed, stage-by-stage analysis for source files."""
    
    for result in results_list:
        if "staged_analysis" in result and result["Address"] == "N/A (Source)": # Only print staged analysis for source files
            analysis = result["staged_analysis"]
            
            # Determine overall status of the staging process
            status_style = "bold green" if analysis["Compilation"] == "Success" else "bold red"
            
            panel_content = Text()
            panel_content.append(f"Contract: {result['name']}\n", style="bold cyan")
            panel_content.append(f"Final Risk: {result['Risk Score']}\n\n", style="bold yellow")
            
            # Format status lines
            for step, status in analysis.items():
                icon = "✅" if status not in ["Failed", "Not Detected", "UNPROTECTED!"] else ("🛑" if status == "UNPROTECTED!" else "❌")
                panel_content.append(f"{icon} {step}: {status}\n", style="white")

            console.print(Panel(
                panel_content, 
                title=Text(f"STAGED ANALYSIS: {analysis['Compilation']}", style=status_style), 
                border_style=status_style
            ))
            
def print_results_cli(results_list: List[Dict[str, Any]], console: Console):
    """Prints the analysis results to the console using rich tables."""
    
    console.rule("[bold cyan]DeFi Upgradeability Detection Tool[/bold cyan]")
    
    # Print Deployed Status First
    print_deployed_status(results_list, console)
    
    # Print Staged Analysis for Source Files
    print_staged_results(results_list, console)
    
    # 1. Print Scan Summary Table
    table = Table(
        title=Text("Security Analysis Report (Final Summary)", style="bold yellow"), 
        show_header=True, 
        header_style="bold green", 
        show_lines=True
    )
    
    table.add_column("Contract/Address", style="cyan", justify="left")
    table.add_column("Upgradeability Pattern", style="magenta", justify="center")
    table.add_column("Admin Control Type", style="blue", justify="center")
    table.add_column("Risk Score", justify="center")
    table.add_column("Security Finding", justify="left", overflow="fold")

    for result in results_list:
        score = result["Risk Score"]
        
        # Define styles for the Risk Score based on project specification
        score_style = Style(bold=True)
        if score == "HIGH":
            score_style = Style(bold=True, color="white", bgcolor="red")
        elif score == "MEDIUM":
            score_style = Style(bold=True, color="black", bgcolor="yellow")
        else:
            score_style = Style(bold=True, color="white", bgcolor="green")

        contract_id = result["Address"] if result["Address"] != "N/A (Source)" else result["Contract"]
        
        table.add_row(
            contract_id,
            result["Upgradeability Pattern"],
            result["Admin Control Type"],
            Text(score, style=score_style),
            result["Security Finding"]
        )

    console.print(table)
    
    console.print(Panel(
        f"Analysis complete. Total items scanned: {len(results_list)}.",
        title="[bold blue]Scan Complete[/bold blue]",
        border_style="blue"
    ))


def output_to_file(results_list: List[Dict[str, Any]], format_type: str, filename: str, console: Console):
    """Writes the structured results to the specified file format (JSON or CSV)."""
    
    if format_type == "json":
        console.print(f"⚠️ JSON output skipped. File would have been written to {filename}.", style="dim yellow")
    
    elif format_type == "csv":
        if not results_list:
            console.print("⚠️ No results to write to CSV.")
            return

        # CSV is limited, so we extract only the final summary fields
        summary_fields = ["Contract", "Address", "Upgradeability Pattern", "Admin Control Type", "Risk Score", "Security Finding"]
        try:
            with open(filename, 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=summary_fields)
                writer.writeheader()
                # Use a comprehension to pull only the summary fields
                writer.writerows([{k: v for k, v in res.items() if k in summary_fields} for res in results_list])
            console.print(f"✅ [bold green]Successfully wrote structured CSV report[/bold green] to [cyan]{filename}[/cyan]")
        except IOError as e:
            console.print(f"❌ [bold red]Error writing CSV file:[/bold red] {e}")


def analyze_and_score(analysis_result: Dict[str, Any], contract_address: Optional[str] = None, console: Optional[Console] = None) -> Dict[str, Any]:
    """
    Merges results from detectors and applies the Risk Score logic.
    """
    console = console or Console()
    
    proxy_info = proxy_detector(analysis_result, contract_address, console)
    detected_proxy = proxy_info["pattern"]
    admin_control = proxy_info["admin_control"] 
    
    has_delegatecall = delegatecall_detector(analysis_result)
    is_create2 = create2_detector(analysis_result)

    risk_score = "LOW"
    risk_reason = "No upgradeability patterns detected." 

    # --- Scoring Logic ---
    if detected_proxy == "Skipped (API Failure)":
        risk_score = "MEDIUM"
        risk_reason = "Analysis incomplete. External API failure requires manual inspection."
    
    elif "Proxy" in detected_proxy or "UUPS" in detected_proxy or "Transparent" in detected_proxy or is_create2: # Include CREATE2 in check
        
        # HIGH: Critical vulnerability detected (Source code analysis)
        if "UUPS" in detected_proxy and analysis_result.get("upgrade_function_detected") and analysis_result.get("admin_control") == "None (Public)":
            risk_score = "HIGH"
            risk_reason = "CRITICAL: UUPS detected but upgrade function has NO access control."
            
        # MEDIUM: Centralized control detected (Source code analysis)
        elif "Centralized" in admin_control or "Transparent" in admin_control or analysis_result.get("admin_control") in ["onlyOwner", "TransparentProxyAdmin"]:
            risk_score = "MEDIUM"
            risk_reason = f"Proxy confirmed ({detected_proxy}). Upgrade authority is centralized ({admin_control})."
            
        # LOW: Assumed governance or non-upgradeable
        else:
            risk_reason = f"Upgradeability confirmed ({detected_proxy}), assumed to be governance-secured."
            risk_score = "LOW"
            
        if has_delegatecall:
             pass


    if is_create2:
        risk_reason += f" | Uses CREATE2 for deterministic deployment."
        
    if not "Proxy" in detected_proxy and not is_create2 and "Verified" not in detected_proxy:
        risk_reason = "No upgradeability patterns detected."


    # Prepare final result structure
    results = {
        "Contract": analysis_result["name"] if contract_address is None else analysis_result["name"].replace("...", contract_address[-8:]),
        "Address": contract_address or "N/A (Source)",
        "Upgradeability Pattern": detected_proxy,
        "Admin Control Type": admin_control,
        "Risk Score": risk_score,
        "Security Finding": risk_reason,
        "staged_analysis": analysis_result.get("staged_analysis", {"Status": "Not Applicable"})
    }
    return results

def main():
    """Main function to handle command-line arguments and run the analysis pipeline."""
    console = Console()
    
    if w3.is_connected():
        console.print(f"✅ Web3 Connected to Sepolia RPC. Chain ID: {w3.eth.chain_id}")
    
    parser = argparse.ArgumentParser(
        description="Enhancing DeFi Security: Upgradeability Detection Tool CLI",
        epilog="Analyzes Solidity source (-f) or deployed addresses (-a) for upgradeability patterns and security risks."
    )
    
    # --- FIX: Removed mutual exclusivity group to allow -f and -a together ---
    parser.add_argument('-f', '--file', nargs='+', help='Solidity source file(s) (.sol) to scan.', default=[])
    parser.add_argument('-a', '--address', nargs='+', help='Deployed contract address(es) to scan (e.g., 0x...).', default=[])
    
    # Output group
    parser.add_argument('--json', help='Output results to a JSON file.', type=str)
    parser.add_argument('--csv', help='Output results to a CSV file.', type=str)
    
    args = parser.parse_args()

    # CRITICAL CHECK: Ensure at least one argument was provided (if not using the exclusive group)
    if not args.file and not args.address:
        parser.error("You must provide either source file(s) (-f) or address(es) (-a) to scan.")

    all_results = []
    
    # Combine inputs and process sequentially
    items_to_process = args.file + args.address
    
    for item in items_to_process:
        is_file = item in args.file
        
        if is_file:
            # Source Code Analysis (Slither Hook)
            try:
                analysis_data = slither_analyze(item)
                result = analyze_and_score(analysis_data, contract_address=None, console=console)
                all_results.append(result)
            except Exception as e:
                console.print(f"❌ [bold red]Error[/bold red] processing file [magenta]{item}[/magenta]: {e}")
        else:
            # Bytecode/Storage Analysis (Web3 Hook)
            try:
                # Mock a minimal analysis result for the scoring function to use
                analysis_data = {"name": f"Contract@{item[:8]}...", "proxy_pattern": "Storage Check", "admin_control": "Unknown"}
                result = analyze_and_score(analysis_data, contract_address=item, console=console)
                all_results.append(result)
            except Exception as e:
                console.print(f"❌ [bold red]Error[/bold red] processing address [yellow]{item}[/yellow]: {e}")

    # 2. Reporting
    if all_results:
        print_results_cli(all_results, console)
        
        if args.json:
            output_to_file(all_results, 'json', args.json, console)
        
        if args.csv:
            output_to_file(all_results, 'csv', args.csv, console)
    else:
        console.print("[bold yellow]No contracts were successfully analyzed. Please check inputs.[/bold yellow]")

if __name__ == "__main__":
    main() # Execute the main CLI parser
