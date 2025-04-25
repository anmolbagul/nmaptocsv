NmaptoCSV
============

Description
-----------
A simple python script to convert Nmap output to CSV

Usage
-----
Copy the Nmap `.xml` output files to `nmap_xml` folder.
The processed xlsx or csv files will be in `output` folder.

The `xlsx` files will have filtering capabilities but require `openpyxl`.

```bash
https://github.com/anmolbagul/nmaptocsv.git
cd nmaptocsv
## Copy `.xml` output files to `nmap_xml` folder.
python3 nmaptocsv.py
# OR
python3 nmaptoxlsx.py
```

Dependencies
-----
For `nmaptoxlsx.py` you will require `openpyxl`.

```bash
pip install openpyxl
# OR
pip3 install openpyxl
```

Sample Output
-----
Sorted by Ports

![image](https://github.com/user-attachments/assets/bf4f5094-e477-4be6-8ff3-aa3924c5935c)

Sorted by Hosts

![image](https://github.com/user-attachments/assets/b2d8b848-7e99-4d16-baf6-5eb7807ce085)

