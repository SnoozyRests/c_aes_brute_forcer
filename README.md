# Parallel Computing Coursework 
Jacob J Williams  
Coursework for the Parallel Computing module UWE  
MSc Cyber Security  
UFCFFL-15-M  
  
## Runtime  
All of the implementations possess a makefile that allows simplistic compiling and running of the algorithms.  
The commands to run all of the algorithms are the same.  
1. Navigate to the folder containing the algorithm.  
2. Input "make".  
3. Input "make run"  
4. Observe output.  
  
In order to make the algorithm run in reverse vector search you will have to edit the algorithms code, this design choice is intentional as to avoid a conflict of variables during runtime.  
To do so, navigate the main file to find the dictionary variable, comment out the forward, and uncomment the reverse, then repeat the steps to complile and run aforementioned.
  
 In the forward vector searches, runtime should be relatively quick across all algorithms with the longest being OpenMP at a couple of minutes.  
 In reverse vector searches, the runtime will be longer, with the longest being serial at a rough average of 27 minutes. But the OpenMP and MPI implemenations are significantly faster.  
 
 ## Specification  
Individual Assignment.  
60% of overall mark for the module.  
Split into two components, development project and accompanying logbook.  
Development project is to implement an AES brute force cracker on a provided cyphertext and plaintext, essentially a known plaintext attack.  
The AES decryption can be done with OpenSSL.    
Code has been provided as a starting basis.  
  
## Requirements
Implement a parallelised version of brute force search in:  
1. OpenMP.  
2. OpenMPI.  
3. OpenCL (optional, extra credit).  
  
Then create a logbook containing logs of development progress, an analysis and testing of your implementation, derive conclusions from these.  
Basic write up (logs, design and development) should be 1500 - 3000 words, Analysis should be around 2000 words.  
Whether you include the analysis as a segment in your logbook is up to you, word count is unaffected.  
  
## Deliverables  
1. Each solution, OpenMP / OpenMPI / Serial / Additional, should be committed to its own directory in UWE's gitlab, each should have a makefile. Include a readme with compile and run instructions.  
2. Project should have a folder with documentation for your project and its solutions, including the logbook.
3. Logbook of 1500 - 3000 words. Logbook is for documenting the design process, along with performance analysis of solutions. Log book should be submitted as a PDF to blackboard. Logbook should include links to Git project.  
  
## Mark Distribution  
1. Functionality - 30% - Finding password successfully using parallel methods.  
2. Performance Analysis - 30% - Logbook and testing, conclusions, etc.  
3. Implementation - 35% - Code analysis, programming standards, program structure.  
4. Internal Documentation - 5% - Code comments, UWE standard.  