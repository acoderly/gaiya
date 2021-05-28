# gaiya
Gaiya is some kind of toolkit to extract C&C from elf file.

First use yara to identify the family of the elf file.

Then use idapython script to extract the C&C.
![avatar](img/flowchart.png)

# TODO
Need more words...

# Bugs
ARM
IDA 7.0  10 40 2D E9 STMFD SP! {R4,LR}
IDA 7.2. 10 40 2D E9 PUSH {R4,LR}
