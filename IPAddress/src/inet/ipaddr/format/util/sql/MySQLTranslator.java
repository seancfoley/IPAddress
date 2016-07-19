package inet.ipaddr.format.util.sql;

/**
 * 
 * @author sfoley
 *
 */
public class MySQLTranslator implements IPAddressSQLTranslator {

	@Override
	public void setNetwork(String networkString) {}
	
	@Override
	public StringBuilder matchString(StringBuilder builder, String expression, String match) {
		return builder.append(expression).append(" = '").append(match).append("'");
	}

	@Override
	public StringBuilder matchSubString(StringBuilder builder, String expression,
			char separator, int separatorCount, String match) {
		return builder.append("substring_index(").append(expression).
			append(",'").append(separator).append("',").append(separatorCount).append(") = ").
			append('\'').append(match).append('\'');
	}

	@Override
	public StringBuilder matchSeparatorCount(StringBuilder builder,
			String expression, char separator, int separatorCount) {
		return compareSeparatorCount(builder, expression, separator, "=", separatorCount);
	}

	@Override
	public StringBuilder boundSeparatorCount(StringBuilder builder,
			String expression, char separator, int separatorCount) {
		return compareSeparatorCount(builder, expression, separator, "<=", separatorCount);
	}
	
	private StringBuilder compareSeparatorCount(StringBuilder builder, String expression, char separator, String operator, int separatorCount) {
		return builder.append("LENGTH (").append(expression).
			append(") - LENGTH(REPLACE(").append(expression).append(", '").
			append(separator).append("', '')) ").append(operator).append(" ").append(separatorCount);
	}
}