"""
Process enumeration and selection functionality.
Handles listing processes and obtaining process handles.
"""

import psutil
from typing import List, Tuple, Optional
from rich.console import Console
from rich.table import Table
from rich.text import Text

console = Console()


def list_processes(show_all: bool = False) -> List[Tuple[int, str, float]]:
    """
    Get a list of running processes with optional filtering.
    Returns: List of (pid, name, memory_mb) tuples
    """
    # Common system processes to filter out
    system_processes = {
        'System', 'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
        'services.exe', 'svchost.exe', 'lsass.exe', 'dwm.exe', 'conhost.exe',
        'csrss.exe', 'Registry', 'MemCompression', 'Secure System',
        'sihost.exe', 'taskhostw.exe', 'svchost.exe', 'audiodg.exe',
        'RuntimeBroker.exe', 'SearchIndexer.exe', 'spoolsv.exe'
    }
    
    # Common Windows executables that are typically not user programs
    windows_executables = [
        'explorer.exe', 'dllhost.exe', 'WerFault.exe', 'ApplicationFrameHost.exe'
    ]
    
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
        try:
            pid = proc.info['pid']
            name = proc.info['name']
            memory_mb = proc.info['memory_info'].rss / 1024 / 1024
            
            # Filter out very small processes (< 1 MB) and system processes
            if not show_all:
                # Skip very small processes or specific system processes
                if name in system_processes:
                    continue
                if memory_mb < 1.0:  # Skip processes using less than 1MB
                    continue
                # Skip Windows system executables
                if name.lower() in [x.lower() for x in windows_executables]:
                    continue
            
            processes.append((pid, name, memory_mb))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    # Sort by: 1) Executable type (exe applications first), 2) Memory usage (high to low)
    # This puts likely targets (games, apps) at the top
    def sort_key(proc):
        pid, name, memory = proc
        # Prioritize .exe files and common game/application names
        is_exe = name.lower().endswith('.exe')
        return (not is_exe, -memory)  # False (exe) sorts before True (non-exe)
    
    return sorted(processes, key=sort_key)


def display_process_list(processes: List[Tuple[int, str, float]], show_all: bool = False):
    """Display processes in a formatted table."""
    title = f"Running Processes ({'All' if show_all else 'Filtered - user programs'})"
    table = Table(title=title)
    table.add_column("Index", style="cyan", width=8)
    table.add_column("PID", style="green", width=10)
    table.add_column("Name", style="white", width=40)
    table.add_column("Memory (MB)", style="yellow", width=15, justify="right")
    
    for idx, (pid, name, memory_mb) in enumerate(processes, 1):
        table.add_row(str(idx), str(pid), name, f"{memory_mb:.2f}")
    
    console.print(table)
    
    if not show_all:
        console.print(f"[dim]Showing {len(processes)} filtered processes (user applications)[/dim]")
        console.print("[dim]To see all processes, type 'all' instead of a number[/dim]")


def select_process(processes: List[Tuple[int, str, float]]) -> Optional[Tuple[int, str]]:
    """
    Let user select a process from the list.
    Returns: (pid, name) tuple or None if cancelled
    """
    while True:
        try:
            choice = input("\nSelect process by index, 'all' to show all processes, or 'q' to quit: ").strip()
            if choice.lower() == 'q':
                return None
            if choice.lower() == 'all':
                return 'show_all'  # Special value to trigger reload
            
            idx = int(choice) - 1
            if 0 <= idx < len(processes):
                pid, name, _ = processes[idx]
                return (pid, name)
            else:
                console.print(f"[red]Invalid index. Please enter 1-{len(processes)}[/red]")
        except ValueError:
            console.print("[red]Invalid input. Please enter a number.[/red]")
        except KeyboardInterrupt:
            return None


def is_admin() -> bool:
    """Check if the process is running with administrator privileges."""
    import ctypes
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def check_admin_rights():
    """Check admin rights and display warning if not available."""
    if not is_admin():
        console.print("[bold red]Warning: Administrator rights required for memory access.[/bold red]")
        console.print("[yellow]Some processes may not be accessible without admin privileges.[/yellow]")

