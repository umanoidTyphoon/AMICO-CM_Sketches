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

import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;

import weka.classifiers.Classifier;
import weka.classifiers.meta.Bagging;
import weka.classifiers.meta.FilteredClassifier;
import weka.classifiers.trees.RandomForest;

public class ModelAnalyzer {
	
	private static final int  DEBUG        = 0;
	
	private static final int  EDGE_POS 	   = 0;
	private static final int  HASHCODE_POS = 0;
	private static final int  PARENT_POS   = 0;
	private static final int  CHILD_POS    = 1;
	private static final int  FEATURE_POS  = 1;
	private static final int  SPLIT_POS    = 1;
	
	private static final String INPUT_DIR  = System.getProperty("user.dir") + 
										     "/demo/model_analysis";
	private static final String OUTPUT_DIR = INPUT_DIR + "/out";
	private static final String TEST_FILE  = OUTPUT_DIR + "/" + "3.0-random_trees-2015-11-06_03-17-02.txt";
	
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
			analyzer.writeFormattedStats(new FileReader(TEST_FILE));
		}
	}
	
	public static boolean isNumeric(String s) {
		try {  
			Double.parseDouble(s);  
		}  
		catch(NumberFormatException nfe) {  
			return false;  
		}  
		return true;  
	}

	private void writeFormattedStats(FileReader fr) {
		int line_ID 		= 0;
		int rand_tree_count = 0;
		String line			= null;
		String rootHashCode = null;
		Map<String,String> hashcode_label_mapping = new HashMap<String, String>();
		Map<String,List<String>> edge_split_point_mapping = new HashMap<String, List<String>>();
		Map<String,List<String>> edge_map		  = new HashMap<String,List<String>>();
		
		try {
			BufferedReader br = new BufferedReader(fr);
			line 			  = br.readLine();
			 
			JSONObject randomTreeContainer = new JSONObject();
			while(line != null) {
				boolean termination_condition_0 = line.startsWith("All"); 
				boolean termination_condition_1 = line.startsWith("Random"); 
				boolean termination_condition_2 = line.startsWith("=");
				boolean termination_condition_3 = line.equals("");
				boolean termination_condition_4 = line.startsWith("Size");
				
				if(termination_condition_0 || termination_condition_1 ||
				   termination_condition_2 || termination_condition_3){
				   line = br.readLine();
				   continue;
				}
				
				if(termination_condition_4) {
				   line    = br.readLine();
				   /* DEBUG 
					System.out.println(hashcode_label_mapping);
					System.out.println(edge_map);
					System.out.println(edge_split_point_mapping);*/
					
					JSONArray children 		  = null;
					JSONArray root_splits	  = null;
					JSONObject[] jsonObjArray = new JSONObject[hashcode_label_mapping.keySet().size()];
					for (int i = 0; i < jsonObjArray.length; i++)
						 jsonObjArray[i] = new JSONObject();
					
					int jsonObjArrayIndex		   = 1;
					JSONObject rootJSONObj    	   = jsonObjArray[0];
					List<String> rootChildren 	   = edge_map.get(rootHashCode);
					List<String> childrenToProcess = new ArrayList<String>(rootChildren);

					for (int i = 0; i < rootChildren.size(); i++) {
						 rootChildren.set(i, hashcode_label_mapping.get(rootChildren.get(i)));
					}
					
					children 	= new JSONArray(rootChildren); 
					root_splits = new JSONArray(edge_split_point_mapping.get(rootHashCode));
					rootJSONObj.put("Feature", hashcode_label_mapping.get(rootHashCode));
					rootJSONObj.put("Split Point", root_splits);
					rootJSONObj.put("Children", children);
					
					while(!childrenToProcess.isEmpty()) {
						   JSONObject childJSONObj    = jsonObjArray[jsonObjArrayIndex++];
						   String childHashCode 	  = childrenToProcess.remove(0);
						   String childFeature        = hashcode_label_mapping.get(childHashCode);
						   List<String> childChildren = edge_map.get(childHashCode);
						   if (childChildren != null) {
							   childrenToProcess.addAll(childChildren);
						   
							   for (int i = 0; i < childChildren.size(); i++) {
								    childChildren.set(i, hashcode_label_mapping.get(childChildren.get(i)));
							   }
						   }
						   JSONArray jsonChildChildren = new JSONArray(childChildren);
						   JSONArray child_splits 	   = new JSONArray(edge_split_point_mapping.get(childHashCode));
						   childJSONObj.put("Feature", childFeature);
						   childJSONObj.put("Split Point", child_splits);
						   childJSONObj.put("Children", jsonChildChildren);
					}
					printJSONObjectArray(jsonObjArray);
					
					JSONObject randomTree = new JSONObject();
					for (int i = 0; i < jsonObjArray.length; i++) {
						 JSONObject obj = jsonObjArray[i];
						 randomTree.put("RandomTreeNode" + i, obj);
					} 
					randomTree.put("NumTreeNodes", jsonObjArray.length);
					System.out.println(randomTree);
					
					randomTreeContainer.put("RandomTree" + rand_tree_count++, randomTree);
					
					line_ID = 0;
					rootHashCode 		     = null;
					hashcode_label_mapping   = new HashMap<String, String>();
					edge_split_point_mapping = new HashMap<String, List<String>>();
					edge_map 				 = new HashMap<String,List<String>>();
					continue;
				}
				
				/** Lines are in the following form:
				 * 
				 *  1 - N$RANDOM_TREE_NODE_HASHCODE$ [label="$LABEL$"]
				 *  2 - N$RANDOM_TREE_NODE_HASHCODE$->N$RANDOM_TREE_NODE_HASHCODE$ [label="$SPLIT_POINT$"]
				 *  E.g.:
				 *  1 - N5010be6 [label="1: twold_benign_ratio"]
				 *  2 - N5010be6->N685f4c2e [label=" < 0.12"] 
				 */
				if ((line_ID++ & 1) == 0 ) {// line_ID is even
					 String[] lineSplit  = line.split(" ");
					 String[] labelSplit = null;
					 String hashCode     = lineSplit[HASHCODE_POS];
					 if (line_ID == 1)
						 rootHashCode = hashCode;
					 String label		 = "";
					 
					 for (int i = 1; i < lineSplit.length; i++) {
						  label += lineSplit[i];
					 }
					 
					 labelSplit     = label.split("\"");
					 String feature = labelSplit[FEATURE_POS];
					 
					 hashcode_label_mapping.put(hashCode, feature);
			    }
				else {// line_ID is odd
					 String[] lineSplit  = line.split(" ");
					 String[] labelSplit = null;
					 String edge     	 = lineSplit[EDGE_POS];
					 String[] edgeSplit  = edge.split("->");
					 String parent       = edgeSplit[PARENT_POS];
					 String child        = edgeSplit[CHILD_POS];
					 String label		 = "";
					 
					 for (int i = 1; i < lineSplit.length; i++) {
						  label += lineSplit[i];
					 }
					 
					 labelSplit     = label.split("\"");
					 String split   = labelSplit[SPLIT_POS];
					 split 			= split.replace("<", "");
					 split 			= split.replace(">", "");
					 split			= split.replace("=", "");
					 
					 if (edge_map.containsKey(parent)) {
						 List<String> children = edge_map.get(parent);
						 children.add(child);
					 }
					 else {
						 List<String> children = new ArrayList<String>();
						 children.add(child);
						 edge_map.put(parent, children);	
					 }
					 
					 if (edge_split_point_mapping.containsKey(parent)) {
						 List<String> split_points = edge_split_point_mapping.get(parent);
						 if (!split_points.contains(split))
							 split_points.add(split);
					 }
					 else {
						 List<String> split_points = new ArrayList<String>();
						 split_points.add(split);
						 edge_split_point_mapping.put(parent, split_points);	
					 }
				}
				line = br.readLine();
			}
			randomTreeContainer.put("NumRandomTrees", rand_tree_count);
			
			JSONObject randomForest = new JSONObject();
			randomForest.put("RandomForest", randomTreeContainer);
			
			String filename = new SimpleDateFormat("yyyy-MM-dd_hh-mm-ss").format(new Date());
			filename 	    = "3.0-random_forest-" + filename  + ".json";
			filename		= OUTPUT_DIR + "/" + filename;
			
			PrintWriter writer = new PrintWriter(filename, "UTF-8");
			writer.println(randomForest.toString());
			writer.close();
			
		} catch (IOException | JSONException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
		}
		
	}

	private void printJSONObjectArray(JSONObject[] jsonObjArray) {
		for (JSONObject jsonObject : jsonObjArray){
			 System.out.println(jsonObject.toString());
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