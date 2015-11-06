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
	private static final int  LABEL_POS    = 1;
	private static final int  LEAF_POS     = 1;
	private static final int  LEVEL_POS    = 1;
	private static final int  SPLIT_POS    = 1;
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
		String line			= null;
		String rootHashCode = null;
		/*int max_level = -1;
		Map<String,List<String>> branch_map    = new TreeMap<String, List<String>>();
		Map<String,List<String>> gen_map       = new TreeMap<String, List<String>>();
		Map<String, String> split_point_map    = new HashMap<String, String>();
		Map<String,List<String>> leaf_node_map = new HashMap<String, List<String>>();*/
		Map<String,String> hashcode_label_mapping   = new HashMap<String, String>();
		Map<String,String> edge_split_point_mapping = new HashMap<String, String>();
		Map<String,List<String>> edge_map		    = new HashMap<String,List<String>>();
		
		try {
			BufferedReader br = new BufferedReader(fr);
			line 			  = br.readLine();
			 
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
					 
					 if (edge_map.containsKey(parent)) {
						 List<String> children = edge_map.get(parent);
						 children.add(child);
					 }
					 else {
						 List<String> children = new ArrayList<String>();
						 children.add(child);
						 edge_map.put(parent, children);	
					 }
					 edge_split_point_mapping.put(edge, split);
				}
				line = br.readLine();
			}
			System.out.println(hashcode_label_mapping);
			System.out.println(edge_map);
			System.out.println(edge_split_point_mapping);
			
			JSONArray children 		  = null;
			JSONObject[] jsonObjArray = new JSONObject[hashcode_label_mapping.keySet().size()];
			for (int i = 0; i < jsonObjArray.length; i++)
				 jsonObjArray[i] = new JSONObject();
			
			int jsonObjArrayIndex		   = 1;
			JSONObject rootJSONObj    	   = jsonObjArray[0];
			List<String> rootChildren 	   = edge_map.get(rootHashCode);
			for (int i = 0; i < rootChildren.size(); i++) {
				 rootChildren.set(i, hashcode_label_mapping.get(rootChildren.get(i)));
			}
			
 			List<String> childrenToProcess = new ArrayList<String>(rootChildren);
			
			children = new JSONArray(rootChildren);
			rootJSONObj.put("Feature", hashcode_label_mapping.get(rootHashCode));
			rootJSONObj.put("Split Point", "null");
			rootJSONObj.put("Children", children);
			
			while(!childrenToProcess.isEmpty()) {
				   JSONObject childJSONObj    = jsonObjArray[jsonObjArrayIndex++];
				   String child_feature       = childrenToProcess.remove(0);
				   List<String> childChildren = null;
				   childrenToProcess.addAll(childChildren);
				   
				   JSONArray jsonChildChildren = new JSONArray(childChildren);
				   childJSONObj.put("Feature", child_feature);
				   childJSONObj.put("Split Point", "null");
				   childJSONObj.put("Children", jsonChildChildren);
			}
		} catch (IOException | JSONException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
		}

		
				/*String[] line_split   = line.split(" ");
				String[] branch_split = line_split[BRANCH_POS].split(":");
				String branch_ID	  = branch_split[BRANCH_POS];
				int level			  = Integer.parseInt(branch_ID.split("_")[LEVEL_POS]);
				max_level 			  = (level > max_level) ? level : max_level;
				String child 		  = branch_split[VALUE_POS];
				String feature_String = "";
				 
				feature_String += child + " ";
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
			String id					     = rootChildrenNodes.get(0).split(" ")[NODE_ID_POS].split(":")[VALUE_POS];
			String root_feature			     = id + "_" + rootChildrenNodes.get(0).split(" ")[FEATURE_POS].split(":")[VALUE_POS];
			String root_split_point			 = rootChildrenNodes.get(0).split(" ")[SPLIT_POS].split(":")[VALUE_POS];
			gen_map.put(root_feature, new ArrayList<String>());
			split_point_map.put(root_feature, root_split_point);

			for(int i = 1; i <= max_level; i++) {
				String key = "Branch_";
				key 	  += i;
				List<String> rTreeNodes = branch_map.get(key);
				for (int j = 0; j < rTreeNodes.size(); j++) {
					 String child 		  = rTreeNodes.get(j++);
					 String[] child_split = child.split(" - ");
					 String child_id		  = child_split[0].split(" ")[NODE_ID_POS].split(":")[VALUE_POS];
					 String child_feature  	  = child_id + "_" + child_split[0].split(" ")[FEATURE_POS].split(":")[VALUE_POS];
					 String parent_feature 	  = child_split[0].split(" ")[PARENT_POS].split(":")[VALUE_POS];
					 String child_split_point = child_split[0].split(" ")[SPLIT_POS].split(":")[VALUE_POS]; 
						
					 List<String> children 	 = gen_map.get(parent_feature);
					 children.add(child_feature);
					 // System.out.println("Children of " + parent_feature + ":" + children);
					 split_point_map.put(child_feature, child_split_point);
					 
					 if(!gen_map.keySet().contains(child_feature)) {
					    gen_map.put(child_feature, new ArrayList<String>());
					 }
					 
					 if (child_split.length > 1) {// 'child' DOES contains a leaf
						 String leaf  		   = child_split[LEAF_POS].replaceFirst(" ", "_");
						 List<String> new_leaf = new ArrayList<String>();  
						 
						 if (leaf_node_map.containsKey(child_feature)) {
							 List<String> leaf_list = leaf_node_map.get(child_feature);
							 leaf_list.add(leaf);
							}
						 else {
							 new_leaf.add(leaf);
							 leaf_node_map.put(child_feature, new_leaf);
						 }
						 
					 }
				}
			}
			System.out.println(gen_map);
			System.out.println(leaf_node_map);
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
				   childJSONObj.put("Split Point", split_point_map.get(child_feature));
				   childJSONObj.put("Children", jsonChildChildren);*/
			
			
	}

	private void printJSONObjectArray(JSONObject[] jsonObjArray) {
		for (JSONObject jsonObject: jsonObjArray){
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