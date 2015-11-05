package model.analyzer;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;

import weka.classifiers.Classifier;
import weka.classifiers.meta.Bagging;
import weka.classifiers.meta.FilteredClassifier;
import weka.classifiers.trees.RandomForest;
import weka.classifiers.trees.RandomTree;

public class ModelAnalyzer {
	
	private static final String INPUT_DIR  = System.getProperty("user.dir") + 
										   "/demo/model_analysis";
	private static final String OUTPUT_DIR = INPUT_DIR + "/out";
	
	private static final String TEST_FILE  = OUTPUT_DIR + "/" + "3.0-random_trees-test.txt";
	
	private String input_model = null;
	
	public FilteredClassifier loadFilteredClassifier(String input_model) {
		this.input_model      = INPUT_DIR + "/" + input_model;
		FilteredClassifier fc = null; 
		try {
			FileInputStream inFileStream = new FileInputStream(this.input_model);
			fc = (FilteredClassifier) (new ObjectInputStream(inFileStream)).readObject();
			inFileStream.close();
		} 
		catch (ClassNotFoundException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return fc;
	}

	public static void main(String[] args) throws Exception {
		ModelAnalyzer analyzer 		  		  = new ModelAnalyzer();
		FilteredClassifier filteredClassifier = analyzer.loadFilteredClassifier("default.model");
		RandomForest classifier		          = (RandomForest) filteredClassifier.getClassifier();
		Bagging m_bagger 					  = analyzer.getRandomForest(classifier);
		Classifier[] m_baggerRandomTrees	  = analyzer.getRandomTrees(m_bagger);
		
		// analyzer.writeStats(m_bagger, m_baggerRandomTrees);
		analyzer.writeFormattedStats(new BufferedReader(new FileReader(TEST_FILE)));
		
		/* DEBUG prints
		  
		System.out.println("-------------------------------------------------------------" +
						   " FILTERED CLASSIFIER DESCRIPTION "	 						   +	
						   "-------------------------------------------------------------" );
		System.out.println(filteredClassifier);
		System.out.println("-------------------------------------------------------------" +
				   		   "---------------------------------"	 						   +	
				   		   "-------------------------------------------------------------\n\n");
		
		
		
		System.out.println("-------------------------------------------------------------" +
				   		   " RANDOM FOREST CLASSIFIER DESCRIPTION "	 				       +	
				   		   "-------------------------------------------------------------" );
		System.out.println(classifier);
		
		System.out.println("-------------------------------------------------------------" +
						   "---------------------------------"	 						   +	
		   		   		   "-------------------------------------------------------------" );
		
		
		
		System.out.println("-------------------------------------------------------------" +
		   		   		   " RANDOM FOREST BAGGER DESCRIPTION "	 				       +	
		   		   		   "-------------------------------------------------------------" );
		System.out.println(m_bagger);

		System.out.println("-------------------------------------------------------------" +
						   "---------------------------------"	 						   +	
		   		   		   "-------------------------------------------------------------" );
		
		RandomTree rTree = null;
		for (Classifier randomTreeClassifier : m_baggerRandomTrees)
			 rTree = (RandomTree) randomTreeClassifier;
			 System.out.println("-------------------------------------------------------------" +
		   		   				" RANDOM TREE AS A GRAPH "				 				        +	
		   		   				"-------------------------------------------------------------" );
			 System.out.println(rTree.graph());
			 System.out.println("-------------------------------------------------------------" +
					 			"---------------------------------"	 						    +	
		   		   				"-------------------------------------------------------------" );*/
	}

	private void writeFormattedStats(BufferedReader br) {
		String line	= null;
		
		try {
			do {
				line = br.readLine();
				boolean termination_condition_0 = line.startsWith("Random"); 
				boolean termination_condition_1 = line.startsWith("=");
				boolean termination_condition_2 = line.equals("");
				boolean termination_condition_3 = line.startsWith("Size");
				
				if(termination_condition_0 || termination_condition_1 ||
				   termination_condition_2 || termination_condition_3){
					continue;
				}
				String formattedLine = line.replaceAll(" |", "");
				// Left children
				if (formattedLine.contains("<"));
			}while(line != null);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void writeStats(Bagging m_bagger, Classifier[] randomTrees) {
		String filename 	= new SimpleDateFormat("yyyy-MM-dd_hh-mm-ss").format(new Date());
		String filename2 	= new SimpleDateFormat("yyyy-MM-dd_hh-mm-ss").format(new Date());
		filename 			= "3.0-random_trees-" + filename  + ".txt";
		filename2 			= "3.1-random_trees_graph-" + filename2 + ".txt";
		filename			= OUTPUT_DIR + "/" + filename;
		filename2			= OUTPUT_DIR + "/" + filename2;
		PrintWriter pWriter = null;
		RandomTree rTree 	= null;
		String graphs		= "";
		
		try {
			pWriter = new PrintWriter(filename);
			pWriter.println(m_bagger.toString());
			pWriter.close();
			
			pWriter = new PrintWriter(filename2);
			for (Classifier randomTreeClassifier : randomTrees){
				 rTree = (RandomTree) randomTreeClassifier;
				 graphs += rTree.graph() + "\n\n";
			}
			pWriter.println(graphs);
			pWriter.close();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private Classifier[] getRandomTrees(Bagging m_bagger) {
		Classifier[] randomTrees = null; 
		try {
			randomTrees = m_bagger.get_m_Classifiers();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return randomTrees;
	}

	private Bagging getRandomForest(RandomForest classifier) {
		Bagging m_bagger = null;
		try {
			m_bagger = classifier.getMBagger();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return m_bagger;
	}
	
}
