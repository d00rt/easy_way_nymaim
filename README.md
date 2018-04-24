# Easy Way Nymaim
An IDA Pro script for creating a clearer IDB for Nymaim malware.

Nymaim, to obfuscate its code uses a technique I have called "Unreferenced Call" (I don't know if there is another, more precise, name). To do this, it has some functions (115 in almost every sample I have tested) that receive two parameters. Then it does a mathematical operation between both arguments which will result in the address of the function to be executed. 

This IDA Python script I wrote is calculating the result given by the operation inside the "Unreferenced Call" and adds a comment with the value to where the function would jump. This way, reversing and debugging the binary become much easier.

# Usage/Demo
![Demo](https://raw.githubusercontent.com/d00rt/easy_way_nymaim/master/demo.gif)
