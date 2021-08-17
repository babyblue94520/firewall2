package pers.clare.firewall;


import java.util.Collection;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Pattern;

public class FirewallRule {
    private final static Pattern replace = Pattern.compile("^regex:");

    private ConcurrentMap<String, String> fixedRules = new ConcurrentHashMap<>();

    private final ConcurrentMap<String, String> regexRules = new ConcurrentHashMap<>();

    private Pattern regexRule = null;

    public FirewallRule() {

    }

    public FirewallRule(String... array) {
        add(array);
    }

    public FirewallRule(Collection<String> collection) {
        add(collection);
    }

    public void add(Collection<String> collection) {
        if (collection == null || collection.size() == 0) return;
        for (String data : collection) {
            add(data);
        }
    }

    public void add(String... array) {
        if (array == null || array.length == 0) return;
        for (String data : array) {
            add(data);
        }
    }

    public void add(String data) {
        if (data == null || data.length() == 0) return;
        String rule = replace.matcher(data).replaceFirst("");
        if (data.equals(rule)) {
            fixedRules.put(rule, rule);
        } else {
            regexRules.put(rule, rule);
            regexRule = null;
        }
    }

    public boolean isEmpty() {
        return fixedRules.size() == 0 && regexRules.size() == 0;
    }

    public boolean match(String data) {
        if (isEmpty()) return false;
        if (fixedRules.containsKey(data)) return true;
        if (regexRules.size() == 0) return false;
        if (regexRule == null && (regexRule = toPattern(regexRules.keySet())) == null) return false;
        return regexRule.matcher(data).find();
    }

    private Pattern toPattern(Set<String> regexRules) {
        if (regexRules == null || regexRules.size() == 0) return null;
        return Pattern.compile("^(" + String.join("|", regexRules) + ")$");
    }

    public static void main(String[] args) {
        String[] ips1 = new String[]{
                "127.0.0.1"
                , "0:0:0:0:0:0:0:1"
                , "211.75.38.1"
                , "211.75.39.1"
                , "211.75.40.1"
                , "regex:10(\\.\\d{1,3}){3}"
                , "regex:192\\.168(\\.\\d{1,3}){2}"
                , "regex:169\\.254(\\.\\d{1,3}){2}"
                , "regex:172\\.1[6-9](\\.\\d{1,3}){2}"
                , "regex:172\\.2[0-9](\\.\\d{1,3}){2}"
                , "regex:172\\.3[0-1](\\.\\d{1,3}){2}"
        };
        String[] ips2 = new String[]{
                "127\\.0\\.0\\.1"
                , "0:0:0:0:0:0:0:1"
                , "211\\.75\\.38\\.1"
                , "211\\.75\\.39\\.1"
                , "211\\.75\\.40\\.1"
                , "10(\\.\\d{1,3}){3}"
                , "192\\.168(\\.\\d{1,3}){2}"
                , "169\\.254(\\.\\d{1,3}){2}"
                , "172\\.1[6-9](\\.\\d{1,3}){2}"
                , "172\\.2[0-9](\\.\\d{1,3}){2}"
                , "172\\.3[0-1](\\.\\d{1,3}){2}"
        };
        Pattern ipPattern = ip(ips2);
        FirewallRule firewallRule = new FirewallRule(ips1);
        String[] array = new String[]{
                "127.0.0.1"
                , "192.168.0.1"
                , "10.1.1.1"
                , "0:0:0:0:0:0:0:1"
                , "0:0:0:0:0:0:0:1"
//                ,"199.168.0.1"
//                ,"0:0:0:0:0:0:0:1"
//                ,"172.3.2.1"
//                ,"1:0:0:0:0:0:0:1"
//                ,"3:0:0:0:0:0:0:1"
//                ,"5:0:0:0:0:0:0:1"
        };
        for (String s : array) {
            System.out.println(ipPattern.matcher(s).find());
            System.out.println(firewallRule.match(s));
        }
        int max = 1000000;

        for (int i = 0; i < 2; i++) {
            run(max, () -> {
                for (String s : array) {
                    ipPattern.matcher(s).find();
                }
            });
            run(max, () -> {
                for (String s : array) {
                    firewallRule.match(s);
                }
            });
        }
    }


    public static void run(int max, Runnable runnable) {
        long t = System.currentTimeMillis();
        for (int i = 0; i < max; i++) {
            runnable.run();
        }
        System.out.println(System.currentTimeMillis() - t);
    }

    public static Pattern ip(String[] array) {
        if (array == null || array.length == 0) return null;
        return Pattern.compile("^(" + String.join("|", array) + ")$");
    }
}
