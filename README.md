# GameTool

**GameTool** is a terminal-based memory scanner and editor for Windows 11 that allows you to scan and modify process memory. Perfect for creating game trainers, debugging applications, and analyzing memory values in real-time.

GameTool helps you find and modify memory values in running processes through progressive filtering. Start with a large scan, narrow down the results by changing values in your target application, and eventually pinpoint the exact memory address you want to modify.

## Features

- **Interactive TUI**: Modern terminal interface powered by Rich
- **Process Selection**: Browse and select from all running processes
- **Multiple Data Types**: Support for int8, int16, int32, int64, float, and double
- **Progressive Filtering**: Scan for values and progressively narrow down results
- **Memory Editing**: Modify memory values directly
- **Safe Memory Access**: Chunked reading for performance

## Requirements

- Windows 11 (or Windows 10)
- Python 3.8+
- Administrator privileges (required for memory access)

## Installation

1. Install Python 3.8 or later if you haven't already

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the tool:
```bash
python main.py
```

**Important**: You must run the tool as Administrator to access process memory.

## Usage

### Basic Workflow

1. **Start the tool**: Run `python main.py` (as Administrator)

2. **Select a process**: Choose the target process from the list (e.g., your game)

3. **Choose data type**: Select the data type (default is 4-byte integer)

4. **Initial scan**: Enter the value you're looking for (e.g., 5 pieces of wood)

5. **Filter results**: 
   - Change the value in your game (e.g., gather more wood so you have 10)
   - Select "Next scan" and enter the new value
   - The tool will filter results to only addresses that match both values

6. **Repeat**: Continue filtering until you have a manageable number of results

7. **Edit memory**: View results, select an address, and write a new value

### Example

Let's say you're scanning for health in a game:

1. Start game, note health = 100
2. Initial scan for value: 100
3. Take damage, health = 95
4. Next scan for value: 95
5. Take more damage, health = 90
6. Next scan for value: 90
7. Eventually you'll narrow down to just the health address
8. Edit it to 9999 for unlimited health!

### Menu Options

- **1 - New scan**: Start a fresh scan with a new value
- **2 - Next scan**: Filter existing results with updated value
- **3 - View results**: Display found memory addresses
- **4 - Edit memory**: Select an address and modify its value
- **5 - Change data type**: Switch to a different numeric type
- **6 - Reset**: Clear current scan results
- **7 - Quit**: Exit the tool

### Key Features

- **Smart Filtering**: Automatically filters out system processes to show only user applications by default
- **Type-Ahead**: Type 'all' when selecting processes to show every running process
- **Optimized Scanning**: Chunked memory reading for performance on large processes
- **Visual Feedback**: Progress indicators and color-coded result counts

## Data Types

| Choice | Name    | Size      | Range                    |
|--------|---------|-----------|--------------------------|
| 1      | int8    | 1 byte    | -128 to 127              |
| 2      | int16   | 2 bytes   | -32,768 to 32,767        |
| 3      | int32   | 4 bytes   | -2³¹ to 2³¹-1 (default) |
| 4      | int64   | 8 bytes   | -2⁶³ to 2⁶³-1            |
| 5      | float   | 4 bytes   | Floating point           |
| 6      | double  | 8 bytes   | Double precision          |

## Troubleshooting

### "Failed to attach to process"
- Make sure you're running as Administrator
- Some system processes are protected and cannot be accessed

### "No results found"
- The value might not be in the scanned memory regions
- Try a different data type
- The value might be stored in a different format

### "Scan is taking too long"
- Large processes have many memory regions
- Progress bar will show scan advancement
- Consider filtering multiple times with smaller value changes

## Legal and Ethical Notes

- This tool is for educational and legitimate debugging purposes
- Only scan your own processes or processes you have permission to modify
- Modifying game memory may violate terms of service
- Use responsibly and ethically

## License

This tool is provided as-is for educational purposes.

