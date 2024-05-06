# Gtrace
Gtrace is a tracing utility designed for the Linux operating system, specifically targeting the x86-64 architecture. It provides a detailed hierarchical view of all system calls, library calls, and internal function calls made by a program at runtime, showcasing the relationships between caller and callee functions. This tool is invaluable for developers looking to debug and optimize their applications.

Features
    Detailed Call Hierarchy: Outputs a hierarchical structure to illustrate the caller-callee relationships.
    Argument and Return Value Tracking: Displays arguments and return values alongside their corresponding functions.
    Register Output: If argument details are indeterminate, Gtrace outputs all six registers used for passing arguments on x86-64.
    Enhanced with Dwarf Debugging: Utilizes Dwarf debug information to retrieve argument counts and names for a cleaner and more informative output.

Command Line Options

    --timestamps, -t: Adds a timestamp to each line of output, corresponding to when the function was called.
    --outfile, -o: Directs the output to a specified file instead of standard output.
    --help, -h: Displays helpful information on how to use Gtrace.
    --aggressive, -a: Specifies the number of bytes to dump from function arguments. If an argument is a pointer, this option will dump the specified number of bytes from the memory address.

Installation

Currently, Gtrace must be compiled from source. Ensure you have the necessary development tools installed (e.g., gcc, make). Clone the source from our repository and compile:

bash

git clone [repository-url]
cd gtrace
make
sudo make install

Usage Example

To use Gtrace, you can simply run it from the command line with the desired options. Here is an example command that outputs traced information into a file with timestamps and aggressive memory reading:

bash

gtrace --outfile=trace.txt --timestamps --aggressive=64 ./hello_world

Output Example

The output will be hierarchical and will include the function calls made by ./hello_world, along with timestamps, argument dumps, and other details as specified by the command line options.
