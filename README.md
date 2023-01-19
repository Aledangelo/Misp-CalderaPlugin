# Misp-CalderaPlugin
[Caldera](https://duckduckgo.com/?q=caldera+mitre&t=osx&ia=web) v4.0.0 plugin to automate the creation of an Adversary profile and an Operation, through a description in a structured format provided via the [MISP](https://www.misp-project.org) platform.

![alt text](https://raw.githubusercontent.com/Aledangelo/Misp-CalderaPlugin/main/img/diagram.png)

## Installation
Concise installation steps:
```
git clone https://github.com/Aledangelo/Misp-CalderaPlugin.git
mv Misp-CalderaPlugin/ caldera/plugins/misp
```
Next, install the PIP requirements:
```
python3 -m pip install -r requirements.txt
```
Insert the "misp" entry in the local.yml file, in the "plugins" section:
```
plugins:
- access
- atomic
- compass
- misp
...
```
Final step, start the server:
```
python3 server.py --fresh
```
## Usage
For the correct interpretation of the CTI by the Caldera server it is necessary to describe them on the MISP platform in a specific format.
For the description of the attack, the miter-attack cluster is used, present by default on the MISP platform, which made it possible to create relationships between the attributes and the techniques described in the ATT&CK Matrix.

Specific tags are used to enrich the description of the event to be emulated:

* **attack-flow:X**: used to reconstruct the attack-flow to be reproduced on CALDERA. X is an integer that represents the position of the technique to which it refers (with respect to the others) within the attack process.
* **preliminary**: used for the procedures to be carried out in the preliminary phase.
* **post**: used to identify the procedures to be carried out in a final phase of emulation.
* **fact-source**: used to use the value of the attribute to which the technique is associated as input to the procedure that will be used in the emulation.
* **out-to-fact:X**: used to identify a certain technique whose output will go into input to the technique marked with the tag fact-to-in:X.
* **fact-to-in:X**: used to identify a technique that needs as input the results of the one marked by the out-to-fact:X tag.