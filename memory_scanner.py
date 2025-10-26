"""
Core memory scanning functionality.
Handles reading memory regions, scanning for values, and writing to memory.
"""

import pymem
import struct
from typing import List, Tuple, Optional, Any
from data_types import DataType
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

console = Console()


class MemoryScanner:
    """Handles memory scanning and editing operations."""
    
    def __init__(self, process_name: str, pid: int):
        self.process_name = process_name
        self.pid = pid
        self.pm = None
        self.current_results: List[Tuple[int, Any]] = []  # List of (address, value) tuples
        self.data_type: Optional[DataType] = None
        self.cached_regions: Optional[List[Tuple[int, int]]] = None  # Cache regions to avoid re-scanning
        
    def attach(self) -> bool:
        """Attach to the process."""
        try:
            self.pm = pymem.Pymem(process_name=self.process_name)
            return True
        except Exception as e:
            console.print(f"[red]Failed to attach to process: {e}[/red]")
            return False
    
    def detach(self):
        """Detach from the process."""
        if self.pm:
            try:
                self.pm.close_process()
            except:
                pass
            self.pm = None
    
    def set_data_type(self, data_type: DataType):
        """Set the data type for scanning."""
        self.data_type = data_type
    
    def _read_memory_region(self, start_address: int, size: int) -> Optional[bytes]:
        """Read a memory region safely."""
        try:
            # Try to read the memory region
            data = self.pm.read_bytes(start_address, size)
            return data
        except Exception as e:
            # If read fails for this region, return None
            return None
    
    def _get_readable_memory_regions(self) -> List[Tuple[int, int]]:
        """Get list of readable memory regions as (start, size) tuples."""
        regions = []
        address = 0
        scanned_count = 0
        
        try:
            # Scan full user-mode address space (can be larger than 0x7FFFFFFF on 64-bit)
            while address < 0x7FFFFFFFFFFFFFFF:  # Full 64-bit user space
                try:
                    mbi = self.pm.virtual_query(address)
                    region_size = mbi.RegionSize
                    scanned_count += 1
                    
                    # Log progress every 50 regions for better visibility
                    if scanned_count % 50 == 0:
                        console.print(f"[dim]Scanned {scanned_count:,} memory regions, found {len(regions)} readable... @ {hex(address)}[/dim]", end="\r")
                    
                    # Check if region is committed (STATE = MEM_COMMIT = 0x1000)
                    if mbi.State == 0x1000:
                        regions.append((address, region_size))
                    
                    address += region_size
                except Exception as e:
                    # If virtual_query fails, try to advance by a small amount
                    address += 0x1000  # 4KB page size
                    
        except Exception as e:
            console.print(f"\n[dim]Region scanning stopped: {e}[/dim]")
        
        # Print final status
        console.print(f"\n[dim]Total regions scanned: {scanned_count:,}[/dim]")
        return regions
    
    def scan(self, target_value: Any) -> int:
        """
        Scan memory for matching values.
        Returns: Number of results found
        """
        if not self.data_type:
            raise ValueError("Data type not set")
        
        # Pack the target value into bytes
        try:
            if isinstance(target_value, float):
                target_bytes = struct.pack(self.data_type.struct_code, target_value)
            else:
                target_bytes = struct.pack(self.data_type.struct_code, int(target_value))
        except:
            raise ValueError(f"Invalid value for {self.data_type.name}")
        
        self.current_results.clear()
        
        # Use cached regions if available, otherwise discover them
        if self.cached_regions is None:
            console.print("[cyan]Step 1/2: Discovering readable memory regions...[/cyan]")
            console.print("[dim]This scans the entire address space to find accessible memory regions.[/dim]\n")
            self.cached_regions = self._get_readable_memory_regions()
        
        regions = self.cached_regions
        total_size = sum(size for _, size in regions)
        console.print(f"[green]Found {len(regions)} memory regions to scan ({total_size / 1024 / 1024:.2f} MB total)[/green]")
        console.print(f"[cyan]Scanning memory for value {target_value}...[/cyan]\n")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task(
                f"Region 0/{len(regions)} [{len(self.current_results)} found]", 
                total=total_size
            )
            
            for region_idx, (start_address, size) in enumerate(regions, 1):
                # Update every 10 regions to avoid excessive updates
                if region_idx % 10 == 1:
                    progress.update(
                        task, 
                        description=f"Region {region_idx}/{len(regions)} [{len(self.current_results)} found]"
                    )
                
                # Read in chunks for performance
                chunk_size = 64 * 1024  # 64KB chunks
                for offset in range(0, size, chunk_size):
                    actual_size = min(chunk_size, size - offset)
                    data = self._read_memory_region(start_address + offset, actual_size)
                    
                    if data and len(data) > 0:
                        # Search for matching bytes
                        # Only scan if we have enough data for the data type
                        if len(data) >= self.data_type.size:
                            for i in range(len(data) - self.data_type.size + 1):
                                # Compare bytes
                                if data[i:i + self.data_type.size] == target_bytes:
                                    addr = start_address + offset + i
                                    # Verify by reading the value
                                    try:
                                        val = struct.unpack(self.data_type.struct_code, data[i:i + self.data_type.size])[0]
                                        self.current_results.append((addr, val))
                                    except:
                                        pass
                    
                    progress.update(task, advance=min(actual_size, size - offset))
        
        console.print(f"\n[green]Scan complete! Found {len(self.current_results)} addresses[/green]\n")
        return len(self.current_results)
    
    def filter_scan(self, new_value: Any) -> int:
        """
        Filter existing results by scanning them for a new value.
        Returns: Number of results remaining
        """
        if not self.data_type:
            raise ValueError("Data type not set")
        
        # Pack the new target value
        try:
            if isinstance(new_value, float):
                target_bytes = struct.pack(self.data_type.struct_code, new_value)
            else:
                target_bytes = struct.pack(self.data_type.struct_code, int(new_value))
        except:
            raise ValueError(f"Invalid value for {self.data_type.name}")
        
        new_results = []
        
        for address, _ in self.current_results:
            try:
                # Re-read the value at this address
                data = self._read_memory_region(address, self.data_type.size)
                if data and data == target_bytes:
                    val = struct.unpack(self.data_type.struct_code, data)[0]
                    new_results.append((address, val))
            except:
                continue
        
        self.current_results = new_results
        return len(self.current_results)
    
    def get_results(self) -> List[Tuple[int, Any]]:
        """Get the current scan results."""
        return self.current_results
    
    def write_value(self, address: int, value: Any) -> bool:
        """
        Write a value to a memory address.
        Returns: True if successful, False otherwise
        """
        if not self.data_type:
            raise ValueError("Data type not set")
        
        try:
            if isinstance(value, float):
                packed = struct.pack(self.data_type.struct_code, value)
            else:
                packed = struct.pack(self.data_type.struct_code, int(value))
            
            self.pm.write_bytes(address, packed, self.data_type.size)
            return True
        except Exception as e:
            console.print(f"[red]Failed to write memory: {e}[/red]")
            return False

