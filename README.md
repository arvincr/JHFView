# JHFView
Cortex-M Core MCU HardFault Analysis Tool

This tool read Core Register content and Stack content throught J-Link, and analyze the reason cause HardFault and the location HardFault Happening

![](https://github.com/XIVN1987/JHFView/blob/master/%E6%88%AA%E5%9B%BE1.jpg)

note 1: make sure there is no code in your HardFault_Handler

note 2: Call Stack analysis need disassembly file, now support Keil MDK and GCC

note 3: to run this software, you need Python 2.7 and PyQt4

beyond that, this tool will also print analysis result of disassembly file, that is functions the function calls
![](https://github.com/XIVN1987/JHFView/blob/master/%E6%88%AA%E5%9B%BE2.jpg)

and which functions call this function
![](https://github.com/XIVN1987/JHFView/blob/master/%E6%88%AA%E5%9B%BE3.jpg)
