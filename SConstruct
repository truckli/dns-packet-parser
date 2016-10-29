import os
units = ["testcases.cpp"]

for f in os.listdir("."):
    if f.endswith('.cpp') and f != "testcases.cpp":
        units.append(f)
    if f.endswith('.c'):
        units.append(f)
        
Program("t",  units, CXXFLAGS="-std=c++0x -g", LIBS=['pcap'])
