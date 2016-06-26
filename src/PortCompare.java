import java.util.Comparator;


public class PortCompare implements Comparator<Port> {

	@Override
	public int compare(Port arg0, Port arg1) {
		int a = arg0.getAmount();
		int b = arg1.getAmount();
		
		if (a > b)
			return -1;
		else if (a < b)
			return 1;
		else
			return 0;
	}

}
