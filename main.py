"""
Main entry point for the Memory Scanner Tool.
Orchestrates all components and handles the main application loop.
"""

from process_manager import list_processes, display_process_list, select_process, check_admin_rights
from memory_scanner import MemoryScanner
from ui import (
    display_welcome,
    display_main_menu,
    choose_data_type,
    get_scan_value,
    display_scan_results,
    display_addresses,
    select_address_to_edit,
    get_new_value
)
from data_types import DataType, INT32
from rich.console import Console

console = Console()


def main():
    """Main application entry point."""
    # Display welcome
    display_welcome()
    
    # Check admin rights
    check_admin_rights()
    
    # Get process list and let user select one
    show_all = False
    
    while True:
        console.print("\n[bold]Loading processes...[/bold]")
        processes = list_processes(show_all=show_all)
        
        if not processes:
            console.print("[red]No processes found.[/red]")
            return
        
        # Display and select process
        display_process_list(processes, show_all=show_all)
        selected = select_process(processes)
        
        if selected == 'show_all':
            # User wants to see all processes
            show_all = True
            continue
        elif not selected:
            console.print("[yellow]No process selected. Exiting.[/yellow]")
            return
        else:
            break
    
    pid, name = selected
    console.print(f"\n[green]Selected process: {name} (PID: {pid})[/green]")
    
    # Initialize scanner and attach
    scanner = MemoryScanner(name, pid)
    if not scanner.attach():
        console.print("[red]Failed to attach to process. Make sure you have admin rights.[/red]")
        return
    
    # Choose data type
    console.print("\n[bold]Choose data type for scanning:[/bold]")
    data_type = choose_data_type()
    scanner.set_data_type(data_type)
    console.print(f"[green]Using data type: {data_type.name} ({data_type.size} bytes)[/green]")
    
    # Main loop
    scanning_started = False
    
    try:
        while True:
            # Display menu
            menu_choice = display_main_menu()
            
            if menu_choice == '1':  # New scan
                value = get_scan_value(data_type)
                if value is not None:
                    console.print(f"\n[cyan]Scanning for value: {value}[/cyan]")
                    count = scanner.scan(value)
                    display_scan_results(count, data_type)
                    scanning_started = True
            
            elif menu_choice == '2':  # Next scan (filter)
                if not scanning_started:
                    console.print("[red]No scan results to filter. Perform a scan first.[/red]")
                    continue
                
                console.print("[yellow]Change the value in your game, then press Enter to filter...[/yellow]")
                input()
                
                value = get_scan_value(data_type)
                if value is not None:
                    console.print(f"\n[cyan]Filtering results for value: {value}[/cyan]")
                    count = scanner.filter_scan(value)
                    display_scan_results(count, data_type)
            
            elif menu_choice == '3':  # View results
                if not scanning_started:
                    console.print("[red]No scan results to display. Perform a scan first.[/red]")
                    continue
                
                results = scanner.get_results()
                if results:
                    display_addresses(results)
                else:
                    console.print("[red]No results to display.[/red]")
            
            elif menu_choice == '4':  # Edit memory
                if not scanning_started:
                    console.print("[red]No scan results to edit. Perform a scan first.[/red]")
                    continue
                
                results = scanner.get_results()
                if not results:
                    console.print("[red]No results to edit.[/red]")
                    continue
                
                # Show addresses
                display_addresses(results, page_size=50)
                
                # Select address
                address = select_address_to_edit(results)
                if address is None:
                    continue
                
                # Get current value
                current_value = next((val for addr, val in results if addr == address), None)
                if current_value is None:
                    console.print("[red]Could not find value for selected address.[/red]")
                    continue
                
                # Get new value
                new_value = get_new_value(data_type, current_value)
                if new_value is None:
                    continue
                
                # Write to memory
                console.print(f"\n[yellow]Writing {new_value} to {hex(address)}...[/yellow]")
                if scanner.write_value(address, new_value):
                    console.print("[green]Successfully wrote to memory![/green]")
                    # Re-read to verify
                    console.print("[cyan]Verifying...[/cyan]")
                    scanner.filter_scan(new_value)
                    console.print(f"[green]Verification complete. Results updated.[/green]")
                else:
                    console.print("[red]Failed to write to memory.[/red]")
            
            elif menu_choice == '5':  # Change data type
                new_type = choose_data_type()
                if new_type.name != data_type.name:
                    console.print(f"[yellow]Changing data type from {data_type.name} to {new_type.name}...[/yellow]")
                    console.print("[yellow]Current scan results will be cleared.[/yellow]")
                    data_type = new_type
                    scanner.set_data_type(data_type)
                    scanning_started = False
            
            elif menu_choice == '6':  # Reset
                console.print("[yellow]Resetting scanner...[/yellow]")
                scanning_started = False
                console.print("[green]Scanner reset complete.[/green]")
            
            elif menu_choice == '7':  # Quit
                console.print("[yellow]Goodbye![/yellow]")
                break
    
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
    except Exception as e:
        console.print(f"\n[red]An error occurred: {e}[/red]")
    finally:
        scanner.detach()


if __name__ == "__main__":
    main()

