package pers.clare.firewall;
/**
 * 
 * 防火牆解析狀態
 */
public class FirewallStatus {
	//拒絕訪問受保護
	public static final int ACCESS_DEFEND_DENIED = -3;
	//拒絕跨域訪問
	public static final int CROSS_ACCESS_DENIED = -2;
	//拒絕訪問
	public static final int ACCESS_DENIED = -1;
	//待驗證訪問
	public static final int ACCESS = 0;
	//待驗證跨域訪問
	public static final int CROSS_ACCESS = 1;
	//忽略路徑訪問
	public static final int IGNORE_PATH_ACCESS = 2;
	//忽略跨域路徑訪問
	public static final int IGNORE_PATH_CROSS_ACCESS = 3;
}
