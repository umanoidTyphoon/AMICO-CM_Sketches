package model.analyzer;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;

import jdk.nashorn.api.scripting.JSObject;
import weka.classifiers.Classifier;
import weka.classifiers.meta.Bagging;
import weka.classifiers.meta.FilteredClassifier;
import weka.classifiers.trees.RandomForest;

public class ModelAnalyzer {
	
	private static final int  DEBUG        = 0;
	private static final int  LEFT_CHILD   = 0;
	private static final int  RIGHT_CHILD  = 1;
	
	private static final int  BRANCH_POS   = 0;
	private static final int  FEATURE_POS  = 1;
	private static final int  LEVEL_POS    = 1;
	private static final int  SPLIT_POS    = 2;
	private static final int  PARENT_POS   = 3;
	private static final int  VALUE_POS	   = 1;
	
	private static final String INPUT_DIR  = System.getProperty("user.dir") + 
										   "/demo/model_analysis";
	private static final String OUTPUT_DIR = INPUT_DIR + "/out";
	private static final String TEST_FILE  = OUTPUT_DIR + "/" + "3.0-random_trees-test2.txt";
	
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
		int debug = Integer.parseInt(args[0]);
		
		ModelAnalyzer analyzer 		  		  = new ModelAnalyzer();
		FilteredClassifier filteredClassifier = analyzer.loadFilteredClassifier("default.model");
		RandomForest classifier		          = (RandomForest) filteredClassifier.getClassifier();
		Bagging m_bagger 					  = analyzer.getRandomForest(classifier);
		Classifier[] m_baggerRandomTrees	  = analyzer.getRandomTrees(m_bagger);
		
		if (debug == DEBUG) {
			analyzer.writeStats(m_bagger, m_baggerRandomTrees);
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
		else {
			analyzer.writeFormattedStats(new BufferedReader(new FileReader(TEST_FILE)));
		}
	}

	private void writeFormattedStats(BufferedReader br) {
		String line	  = null;
		int max_level = -1;
		Map<String,List<String>> branch_map = new TreeMap<String, List<String>>();
		Map<String,List<String>> gen_map = new TreeMap<String, List<String>>();
		
		try {
			line = br.readLine();
			while(line != null) {
				boolean termination_condition_0 = line.startsWith("Random"); 
				boolean termination_condition_1 = line.startsWith("=");
				boolean termination_condition_2 = line.equals("");
				boolean termination_condition_3 = line.startsWith("Size");
				
				if(termination_condition_0 || termination_condition_1 ||
				   termination_condition_2 || termination_condition_3){
					line = br.readLine();
					continue;
				}
				// Commented out because of old format
				// String formattedLine = line.replaceAll(" |", "");
				
				String[] line_split   = line.split(" ");
				String[] branch_split = line_split[BRANCH_POS].split(":");
				String branch_ID	  = branch_split[BRANCH_POS];
				int level			  = Integer.parseInt(branch_ID.split("_")[LEVEL_POS]);
				max_level 			  = (level > max_level) ? level : max_level;
				String child 		  = branch_split[1];
				String feature_String = "";
				 
				feature_String 	  += child + " ";
				for (int i = 1; i < line_split.length; i++) {
					 feature_String += line_split[i] + " ";
				}
				List<String> features = new ArrayList<String>();
				features.add(feature_String);
				 
				if (branch_map.containsKey(branch_ID)) {
					List<String> feature_List = branch_map.get(branch_ID);
					feature_List.addAll(features);
				}
				else {
					branch_map.put(branch_ID, features);
				}
				line = br.readLine();
			}
			System.out.println(branch_map);

			List<String> rootChildrenNodes	 = branch_map.get("Branch_0");
			// ASSUMPTION: the root is not a leaf...
			String root_feature			     = rootChildrenNodes.get(0).split(" ")[FEATURE_POS].split(":")[VALUE_POS];
			String root_split_point			 = rootChildrenNodes.get(0).split(" ")[SPLIT_POS].split(":")[VALUE_POS];
			gen_map.put(root_feature, new ArrayList<String>());

			for(int i = 1; i <= max_level; i++) {
				String key = "Branch_";
				key 	  += i;
				List<String> rTreeNodes = branch_map.get(key);
				for (int j = 0; j < rTreeNodes.size(); j++) {
					String child 		   = rTreeNodes.get(j++);
					String child_feature  = child.split(" ")[FEATURE_POS].split(":")[VALUE_POS];
					String parent_feature = child.split(" ")[PARENT_POS].split(":")[VALUE_POS];

					List<String> children = gen_map.get(parent_feature);
					children.add(child_feature);

					gen_map.put(child_feature, new ArrayList<String>());
				}
			}
			System.out.println(gen_map);
			JSONArray children 		  = null;
			JSONObject[] jsonObjArray = new JSONObject[gen_map.keySet().size()];
			for (int i = 0; i < jsonObjArray.length; i++)
				 jsonObjArray[i] = new JSONObject();
			
			int jsonObjArrayIndex		   = 1;
			JSONObject rootJSONObj    	   = jsonObjArray[0];
			List<String> rootChildren 	   = gen_map.get(root_feature);
			List<String> childrenToProcess = new ArrayList<String>(rootChildren);
			
			children = new JSONArray(rootChildren);
			rootJSONObj.put("Feature", root_feature);
			rootJSONObj.put("Split Point", root_split_point);
			rootJSONObj.put("Children", children);
			
			while(!childrenToProcess.isEmpty()) {
				   JSONObject childJSONObj    = jsonObjArray[jsonObjArrayIndex++];
				   String child_feature       = childrenToProcess.remove(0);
				   List<String> childChildren = gen_map.get(child_feature);
				   childrenToProcess.addAll(childChildren);
					
				   JSONArray jsonChildChildren = new JSONArray(childChildren);
				   childJSONObj.put("Feature", child_feature);
				   childJSONObj.put("Split Point", root_split_point);
				   childJSONObj.put("Children", jsonChildChildren);
			}
			
			System.out.println(jsonObjArray[5].toString());
		} catch (IOException | JSONException e) {
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
		/*RandomTree rTree 	= null;
		String graphs		= "";*/
		
		try {
			pWriter = new PrintWriter(filename);
			pWriter.println(m_bagger.toString());
			pWriter.close();
			
			/*pWriter = new PrintWriter(filename2);
			for (Classifier randomTreeClassifier : randomTrees){
				 rTree = (RandomTree) randomTreeClassifier;
				 graphs += rTree.graph() + "\n\n";
			}
			pWriter.println(graphs);
			pWriter.close();*/
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@SuppressWarnings("unused")
	// TODO To be implemented...
	private String format_DFS_String(String DFS_visit) {
		Map<String,List<String>> branch_map = new HashMap<String, List<String>>();
		String[] lines 				  		= DFS_visit.split(System.getProperty("line.separator"));
		/* String format in input - Branch_i:$LEFT_OR_RIGHT$ Feature:$FEATURE_NAME$ 
		 * Split_point:$SPLIT_POINT_DOUBLE$
		 */
		for (String line : lines) {
			 String[] line_split   = line.split(" ");
			 String[] branch_split = line_split[0].split(":");
			 String branch_ID	   = branch_split[0];
			 String child 		   = branch_split[1];
			 String feature_String = "";
			 
			 feature_String 	  += child;
			 for (int i = 1; i < line_split.length; i++) {
				  feature_String += line_split[i];
			 }
			 List<String> features = new ArrayList<String>();
			 features.add(feature_String);
			 
			 if (branch_map.containsKey(branch_ID)) {
				 List<String> feature_List = branch_map.get(branch_ID);
				 feature_List.addAll(features);
			 }
			 else {
				 branch_map.put(branch_ID, features);
			}
		}
		System.out.println(branch_map);
		return DFS_visit;
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