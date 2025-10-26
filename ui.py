"""
Rich-based TUI components for the memory scanner.
Provides menus, result display, and interactive prompts.
"""

from typing import List, Tuple, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from data_types import DataType, DATA_TYPES

console = Console()


def display_welcome():
    """Display welcome message."""
    welcome_text = """
[bold cyan]Memory Scanner Tool[/bold cyan]
A tool for scanning and editing process memory.
"""
    console.print(Panel(welcome_text, title="Welcome"))


def display_main_menu() -> str:
    """Display main menu and get user choice."""
    menu_text = """
[bold]Main Menu:[/bold]
[green]1[/green] - New scan (start fresh)
[green]2[/green] - Next scan (filter results)
[green]3[/green] - View results
[green]4[/green] - Edit memory
[green]5[/green] - Change data type
[green]6[/green] - Reset
[green]7[/green] - Quit
"""
    console.print(menu_text)
    
    while True:
        choice = input("Select option: ").strip()
        if choice in ['1', '2', '3', '4', '5', '6', '7']:
            return choice
        console.print("[red]Invalid choice. Please enter 1-7.[/red]")


def choose_data_type() -> DataType:
    """Let user choose a data type."""
    table = Table(title="Data Types")
    table.add_column("Choice", style="cyan", width=8)
    table.add_column("Name", style="white", width=15)
    table.add_column("Size", style="yellow", width=10)
    table.add_column("Range", style="green")
    
    for key, dt in DATA_TYPES.items():
        range_str = f"{dt.min_val} to {dt.max_val}" if dt.min_val is not None else "N/A"
        table.add_row(key, dt.name, f"{dt.size} bytes", range_str)
    
    console.print(table)
    
    while True:
        choice = input(f"\nSelect data type (default: 3 for int32): ").strip()
        if choice == '':
            choice = '3'
        if choice in DATA_TYPES:
            return DATA_TYPES[choice]
        console.print(f"[red]Invalid choice. Please enter 1-6.[/red]")


def get_scan_value(data_type: DataType) -> Optional[float]:
    """Prompt user for a value to scan."""
    while True:
        try:
            value_str = input(f"\nEnter value to search for ({data_type.name}): ").strip()
            if value_str.lower() == 'c':
                return None
            
            if data_type.name in ('float', 'double'):
                return float(value_str)
            else:
                return int(value_str)
        except ValueError as e:
            console.print(f"[red]Invalid {data_type.name} value: {e}[/red]")
        except KeyboardInterrupt:
            return None


def display_scan_results(count: int, data_type: DataType):
    """Display scan result count."""
    color = "green" if count < 1000 else "yellow" if count < 10000 else "red"
    console.print(f"\n[bold {color}]Found {count} addresses matching the value[/bold {color}]")


def display_addresses(results: List[Tuple[int, any]], page_size: int = 20):
    """Display scan result addresses in paginated format."""
    if not results:
        console.print("[red]No results to display.[/red]")
        return
    
    total_pages = (len(results) + page_size - 1) // page_size
    current_page = 1
    
    while True:
        start_idx = (current_page - 1) * page_size
        end_idx = min(start_idx + page_size, len(results))
        page_results = results[start_idx:end_idx]
        
        table = Table(title=f"Results (Page {current_page}/{total_pages})")
        table.add_column("Index", style="cyan", width=8)
        table.add_column("Address", style="green", width=20)
        table.add_column("Value", style="yellow", width=20)
        
        for idx, (address, value) in enumerate(page_results, start=start_idx + 1):
            addr_str = f"0x{address:016X}"
            table.add_row(str(idx), addr_str, str(value))
        
        console.print(table)
        
        if total_pages == 1:
            break
        
        nav = input(f"\nPage {current_page}/{total_pages}: [N]ext, [P]revious, [Q]uit: ").strip().lower()
        
        if nav == 'n' and current_page < total_pages:
            current_page += 1
        elif nav == 'p' and current_page > 1:
            current_page -= 1
        elif nav == 'q':
            break


def select_address_to_edit(results: List[Tuple[int, any]]) -> Optional[int]:
    """Let user select an address to edit."""
    if not results:
        console.print("[red]No results available.[/red]")
        return None
    
    while True:
        try:
            idx = input(f"\nSelect address index (1-{len(results)}) or 'c' to cancel: ").strip()
            if idx.lower() == 'c':
                return None
            
            idx = int(idx) - 1
            if 0 <= idx < len(results):
                return results[idx][0]
            else:
                console.print(f"[red]Invalid index. Please enter 1-{len(results)}[/red]")
        except ValueError:
            console.print("[red]Invalid input.[/red]")
        except KeyboardInterrupt:
            return None


def get_new_value(data_type: DataType, current_value: any) -> Optional[float]:
    """Prompt user for new value to write."""
    console.print(f"\nCurrent value: [cyan]{current_value}[/cyan]")
    console.print(f"Data type: [cyan]{data_type.name}[/cyan]")
    
    while True:
        try:
            value_str = input(f"Enter new value (or 'c' to cancel): ").strip()
            if value_str.lower() == 'c':
                return None
            
            if data_type.name in ('float', 'double'):
                return float(value_str)
            else:
                val = int(value_str)
                # Check bounds if applicable
                if data_type.min_val is not None and (val < data_type.min_val or val > data_type.max_val):
                    console.print(f"[yellow]Warning: Value out of range for {data_type.name}[/yellow]")
                    confirm = input("Continue anyway? (y/n): ").strip().lower()
                    if confirm != 'y':
                        continue
                return val
        except ValueError as e:
            console.print(f"[red]Invalid {data_type.name} value: {e}[/red]")
        except KeyboardInterrupt:
            return None

