package model.analyzer;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;

import weka.classifiers.meta.FilteredClassifier;
import weka.classifiers.trees.RandomForest;

public class ModelAnalyzer {
	
	public static final String INPUT_DIR = System.getProperty("user.dir") + 
										   "/demo/model_analysis";
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

	public static void main(String[] args) {
		ModelAnalyzer analyzer 		  = new ModelAnalyzer();
		FilteredClassifier filteredClassifier = analyzer.loadFilteredClassifier("default.model");
		RandomForest classifier		          = (RandomForest) filteredClassifier.getClassifier();
		
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
		
	}

}
