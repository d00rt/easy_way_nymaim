# Easy Way Nymaim
An IDA Pro script for creating a clearer idb for nymaim malware

Nymaim, to ofuscate his code uses a technique I have called "unreferenced call" (I don't know if there is other more precise name). 
To do this, it has some functions (115 in almos every sample I have tested it) that receive two parameters, it does an operation between both arguments and the result of the operation will be the address of the function which finaly the program executes. 
What this script does is calculate the result given by the operation inside the "unreferenced call" and add a comment with the value where the function will jump. This way debugging the binary file is much easier.

# Usage/Demo
![Demo](https://raw.githubusercontent.com/d00rt/easy_way_nymaim/master/demo.gif)
