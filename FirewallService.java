package pers.clare.firewall;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * 防火牆
 */
public class FirewallService {
    private static final Pattern PROTOCOL_PATTERN = Pattern.compile("^http[s]?");

    private FirewallRule defendPath = new FirewallRule();
    private FirewallRule defendAllowIp = new FirewallRule();
    private FirewallRule defendAllowRemoteIp = new FirewallRule();

    private FirewallRule allowIp = new FirewallRule();
    private FirewallRule allowRemoteIp = new FirewallRule();

    private FirewallRule blockIp = new FirewallRule();
    private FirewallRule blockRemoteIp = new FirewallRule();

    private FirewallRule ignorePath = new FirewallRule();

    private FirewallRule allowCrossOrigin = new FirewallRule();

    public FirewallService() {
    }

    public void addRules(FirewallProperties properties) {
        defendPath.add(properties.getDefendPath());
        defendAllowIp.add(properties.getDefendAllowIp());
        defendAllowRemoteIp.add(properties.getDefendAllowIp());

        allowIp.add(properties.getAllowIp());
        allowRemoteIp.add(properties.getAllowRemoteIp());

        blockIp.add(properties.getBlockIp());
        blockRemoteIp.add(properties.getBlockRemoteIp());

        ignorePath.add(properties.getIgnorePath());

        allowCrossOrigin.add(properties.getAllowCrossOrigin());
    }

    public void resetRule(FirewallProperties properties) {
        FirewallRule defendPath = new FirewallRule();
        FirewallRule defendAllowIp = new FirewallRule();
        FirewallRule defendAllowRemoteIp = new FirewallRule();

        FirewallRule allowIp = new FirewallRule();
        FirewallRule allowRemoteIp = new FirewallRule();

        FirewallRule blockIp = new FirewallRule();
        FirewallRule blockRemoteIp = new FirewallRule();

        FirewallRule ignorePath = new FirewallRule();

        FirewallRule allowCrossOrigin = new FirewallRule();

        if (properties != null) {
            defendPath.add(properties.getDefendPath());
            defendAllowIp.add(properties.getDefendAllowIp());
            defendAllowRemoteIp.add(properties.getDefendAllowRemoteIp());

            allowIp.add(properties.getAllowIp());
            allowRemoteIp.add(properties.getAllowRemoteIp());

            blockIp.add(properties.getBlockIp());
            blockRemoteIp.add(properties.getBlockRemoteIp());

            ignorePath.add(properties.getIgnorePath());

            allowCrossOrigin.add(properties.getAllowCrossOrigin());
        }

        this.defendPath = defendPath;
        this.defendAllowIp = defendAllowIp;
        this.defendAllowRemoteIp = defendAllowRemoteIp;

        this.allowIp = allowIp;
        this.allowRemoteIp = allowRemoteIp;

        this.blockIp = blockIp;
        this.blockRemoteIp = blockRemoteIp;

        this.ignorePath = ignorePath;

        this.allowCrossOrigin = allowCrossOrigin;
    }

    /**
     * 解析請求.
     */
    public int parse(
            String path
            , String url
            , String origin
            , String clientIp
            , String remoteIp
    ) {
        // 連線IP 跟 客戶端IP是否相同
        if (Objects.equals(clientIp, remoteIp)) {
            return parse(path, url, origin, clientIp);
        } else {
            return parseDiff(path, url, origin, clientIp, remoteIp);
        }
    }

    /**
     * 連線IP和客戶端IP相同
     */
    public int parse(
            String path
            , String url
            , String origin
            , String ip
    ) {
        //檢查是否為拒絕IP
        if (isBlockIp(ip)) {
            return FirewallStatus.ACCESS_DENIED;
        }
        //檢查是否為允許IP
        if (!isAllowIp(ip)) {
            return FirewallStatus.ACCESS_DENIED;
        }

        if (isDefendPath(path) && !isDefendAllowIp(ip)) {
            return FirewallStatus.ACCESS_DEFEND_DENIED;
        }

        //跨域請求
        if (isCross(origin, url)) {
            if (!isCrossAllowOrigin(ip)) {
                return FirewallStatus.CROSS_ACCESS_DENIED;
            }
            if (isIgnorePath(path)) {
                return FirewallStatus.IGNORE_PATH_CROSS_ACCESS;
            }
            return FirewallStatus.CROSS_ACCESS;
            //非跨域請求
        } else {
            //是否為忽略的請求
            if (isIgnorePath(path)) {
                return FirewallStatus.IGNORE_PATH_ACCESS;
            }
            return FirewallStatus.ACCESS;
        }
    }


    /**
     * 連線IP和客戶端IP 不相同
     */
    private int parseDiff(
            String url
            , String path
            , String origin
            , String clientIp
            , String remoteIp
    ) {
        //檢查是否為拒絕IP
        if (isBlockIp(clientIp, remoteIp)) {
            return FirewallStatus.ACCESS_DENIED;
        }
        //檢查是否為允許IP
        if (!isAllowIp(clientIp, remoteIp)) {
            return FirewallStatus.ACCESS_DENIED;
        }
        // 檢查是否可訪問保護的路徑
        if (!(isDefendPath(path) && isDefendAllowIp(clientIp, remoteIp))) {
            return FirewallStatus.ACCESS_DEFEND_DENIED;
        }

        //跨域請求
        if (isCross(origin, url)) {
            if (isCrossAllowOrigin(origin)) {
                return FirewallStatus.CROSS_ACCESS_DENIED;
            }
            if (isIgnorePath(path)) {
                return FirewallStatus.IGNORE_PATH_CROSS_ACCESS;
            }
            return FirewallStatus.CROSS_ACCESS;
            //非跨域請求
        } else {
            //是否為忽略的請求
            if (isIgnorePath(path)) {
                return FirewallStatus.IGNORE_PATH_ACCESS;
            }
            return FirewallStatus.ACCESS;
        }
    }

    private boolean isDefendPath(String path) {
        if (defendPath.isEmpty()) return false;
        return defendPath.match(path);
    }

    private boolean isDefendAllowIp(String ip) {
        if (defendAllowIp.isEmpty()) return false;
        return defendAllowIp.match(ip);
    }

    /**
     * IP是否可訪問受保護的路徑
     */
    private boolean isDefendAllowIp(String clientIp, String remoteIp) {
        if (defendAllowRemoteIp.isEmpty()) return isDefendAllowIp(clientIp);
        return defendAllowRemoteIp.match(remoteIp) && isDefendAllowIp(clientIp);
    }

    /**
     * 檢查是否跨域請求.
     */
    private boolean isCross(String origin, String url) {
        if (origin == null || url == null) return false;
        return !url.contains(PROTOCOL_PATTERN.matcher(origin).replaceFirst(""));
    }

    private boolean isAllowIp(String ip) {
        // 沒設定為全通過
        if (allowIp.isEmpty()) return true;
        return allowIp.match(ip);
    }

    private boolean isAllowIp(String remoteIp, String clientIp) {
        // 沒設定為全通過
        if (allowRemoteIp.isEmpty()) return isAllowIp(clientIp);
        return allowRemoteIp.match(remoteIp) && isAllowIp(clientIp);
    }

    private boolean isBlockIp(String ip) {
        if (blockIp.isEmpty()) return false;
        return blockIp.match(ip);
    }

    private boolean isBlockIp(String remoteIp, String clientIp) {
        if (blockRemoteIp.isEmpty()) return isBlockIp(clientIp);
        return blockRemoteIp.match(remoteIp) || isBlockIp(clientIp);
    }

    private boolean isIgnorePath(String path) {
        if (ignorePath.isEmpty()) return false;
        return ignorePath.match(path);
    }

    private boolean isCrossAllowOrigin(String origin) {
        if (allowCrossOrigin.isEmpty()) return false;
        return allowCrossOrigin.match(origin);
    }


    public FirewallRule getDefendPath() {
        return defendPath;
    }

    public FirewallRule getDefendAllowIp() {
        return defendAllowIp;
    }

    public FirewallRule getDefendAllowRemoteIp() {
        return defendAllowRemoteIp;
    }

    public FirewallRule getAllowIp() {
        return allowIp;
    }

    public FirewallRule getAllowRemoteIp() {
        return allowRemoteIp;
    }

    public FirewallRule getBlockIp() {
        return blockIp;
    }

    public FirewallRule getBlockRemoteIp() {
        return blockRemoteIp;
    }

    public FirewallRule getIgnorePath() {
        return ignorePath;
    }

    public FirewallRule getAllowCrossOrigin() {
        return allowCrossOrigin;
    }
}
