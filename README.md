# MHDE

This is a software programme developed to test and evaluate the Multi-hop Distance Estimation(MHDE) protocol proposed by Katerina et. al. 

The source code is written using java JDK8 on Eclipse Neon.2 IDE. The 'src' source folder contains three packages: thesis.mhde, thesis.mhde.crypto and thesis.mhde.element. The package thesis.mhde.crypto contains classes to perform cryptographic functionalities like encryption/decryption, signing/verification, and message binding-and-hiding commitment. This particular implementaion uses RSA cipher, DSA signature scheme and Pederson Commitment scheme. The package thesis.mhde.element contains separate classes to mimic the behaviour of a prover, a verifier, a proxy, a trusted-third party, and a link established between two nodes. 

The class 'Simulator.java' which is in the thesis.mhde package contains the main method to run the programme. In order to this programme it needs two input files. A 'pqgTriple' file(in the input folder) which containes p,q,g values to be used in Pederson Commitment scheme. The input file 'topologyin.tpg' in the 'input' folder defines the topology(as below) with some parameters on which the MHDE protocol is run on. The initial nodes' postions are denoted as xyz-coordinate triple. Anybody who wants to use a different topology have to replace content in the topology file with their data using the suggested format

The structure of 'topologyin.tpg' file:

num_of_paths=5

n_value=256

power_radius=10

path_1=(0.0,5.0,0.0),(7.1,6.0,-0.5),(13.9,4.2,0.1),(23.0,4.7,-1.9),(31.2,2.9,-1.5),(40.6,4.6,-2.3),(50.0,5.0,0.0)

path_2=(0.0,5.0,0.0),(5.0,4.2,-1.4),(12.9,5.2,0.1),(22.6,3.6,-0.1),(26.8,4.9,0.2),(35.9,3.5,-1.7),(42.9,5.3,-1.4),(50.0,5.0,0.0)

path_3=(0.0,5.0,0.0),(4.1,5.4,-0.7),(10.0,7.1,-1.1),(16.0,5.6,-0.8),(24.9,4.8,0.1),(29.3,6.7,-1.4),(34.1,8.7,-2.1),(41.1,7.3,-1.4),(50.0,5.0,0.0)

path_4=(0.0,5.0,0.0),(6.8,5.9,-0.3),(11.4,3.4,1.0),(15.5,4.8,0.6),(19.8,2.9,1.5),(25.0,4.4,-0.1),(33.4,1.4,0.0),(39.6,2.0,-2.2),(45.8,0.1,-1.4),(50.0,5.0,0.0)

path_5=(0.0,5.0,0.0),(5.4,1.3,-3.9),(9.7,2.3,0.0),(15.8,0.4,-2.3),(20.2,3.5,0.7),(24.3,3.0,-0.1),(28.6,4.2,0.8),(34.2,1.7,-0.9),(40.0,3.7,1.5),(45.0,4.35,0.75),(50.0,5.0,0.0)


