package inet.ipaddr.format.util.sql;

/**
 * Used to produce SQL for matching ip address section strings in databases.
 * 
 * Provides SQL conditions using SQL targeting a given database type.
 * 
 * @author sfoley
 *
 */
public interface IPAddressSQLTranslator {
	/**
	 * Called with the network section, taken from an IP address or IP address section, that is being matched, for logging or debugging purposes.
	 * 
	 * @param networkString
	 */
	void setNetwork(String networkString);
	
	/**
	 * Produces an SQL condition that evaluates to true when the given expression matches the given String,
	 * appending the condition to the given string builder.
	 * 
	 * @param builder
	 * @param expression the expression
	 * @param match the String to match with the expression
	 * @return builder with the condition appended
	 */
	StringBuilder matchString(StringBuilder builder, String expression, String match);
	
	/**
	 * Produces an SQL condition that evaluates to true when the given expression matches a substring obtained from the given expression,
	 * appending the condition to the given string builder.
	 * 
	 * @param builder
	 * @param expression the expression
	 * @param match the String to match with a substring of the expression, 
	 * 	the substring being the substring taken from "expression" prior to the separatorCount appearance of the given separator char.
	 *  If there are not that many appearances of the separator char, then the substring is all of the String expression.
	 * @return builder with the condition appended
	 */
	StringBuilder matchSubString(StringBuilder builder, String expression, char separator, int separatorCount, String match);
	
	/**
	 * Produces an SQL condition that evaluates to true when "expression" has exactly a certain number of a given char within,
	 * appending the condition to the given string builder.
	 * 
	 * @param builder
	 * @param expression the expression which must contain the indicated count of the indicated separator char
	 * @param separator the separator char
	 * @param separatorCount the count to  match
	 * @return builder with the condition appended
	 */
	StringBuilder matchSeparatorCount(StringBuilder builder, String expression, char separator, int separatorCount);
	
	/**
	 * Produces an SQL condition that evaluates to true when "expression" has at most a certain number of a given char within,
	 * appending the condition to the given string builder.
	 * 
	 * @param builder
	 * @param expression the expression which must contain at most the indicated count of the indicated separator char
	 * @param separator the separator char
	 * @param separatorCount the count to  match
	 * @return builder with the condition appended
	 */
	StringBuilder boundSeparatorCount(StringBuilder builder, String expression, char separator, int separatorCount);
}