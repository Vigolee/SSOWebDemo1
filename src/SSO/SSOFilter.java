package SSO;

import com.alibaba.fastjson.JSONObject;
import com.sun.deploy.net.HttpResponse;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SSOFilter implements Filter {

    private String cookieName = "SSO_ID";

    private String SSOServiceURL = "http://127.0.0.1:8080/SSOAuth/SSOAuth";

    private String SSOLoginPage = "http://127.0.0.1:8080/SSOAuth/login.jsp";


    public void init(FilterConfig filterConfig) {
        this.cookieName = filterConfig.getInitParameter("cookieName");
        this.SSOServiceURL = filterConfig.getInitParameter("SSOServiceURL");
        this.SSOLoginPage = filterConfig.getInitParameter("SSOLoginPage");
    }

    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        String path = request.getContextPath();
        System.out.println("path: " + path);

        if (request.getRequestURI().equals(request.getContextPath() + "/setCookie")){
            /**
             * 生成Cookie到浏览器
             */
            String ticketKey = request.getParameter("ticketKey");
            int expiry = Integer.parseInt(request.getParameter("expiry"));
            Cookie ticket = new Cookie(cookieName, ticketKey);
            ticket.setPath("/");
            ticket.setMaxAge(expiry);
            response.addCookie(ticket);

            /** 重定向到请求页面 */
            String gotoURL = request.getParameter("gotoURL");
            if (gotoURL != null)
                response.sendRedirect(gotoURL);
        } else if (request.getRequestURI().equals(request.getContextPath() + "/goto")){
            String url = request.getParameter("url");
            String cookieValue = getCookieValue(request);
            String authAction = "?action=resetCookie&cookieValue=";
            response.sendRedirect(this.SSOServiceURL + authAction + cookieValue +"&setCookieURL="+url + "/setCookie&gotoURL="+ url + "/index.jsp");

        } else {
            /** 请求地址 */
            String url = request.getRequestURL().toString();
            /** ticketKey值 */
           String cookieValue = getCookieValue(request);
            /**
             * Cookie没有ticket，重定向到登陆页面
             * Cookie带有ticket，验证ticket
             */
            if (cookieValue.equals("")){
                /**
                 * 第一次登陆,没有ticket，重定向到SSO登陆页面
                 * 传参数：设置cookie的url以及当前请求页面
                 */
                response.sendRedirect(this.SSOLoginPage + "?setCookieURL=" + request.getScheme() + "://"
                        + request.getServerName() + ":" + request.getServerPort()
                        + path + "/setCookie&gotoURL=" + url);
            } else {
                /**
                 * Cookie中有ticket，去SSO验证ticket
                 */
                Map<String, Object> responseMap = SSOAuthCookieService(cookieValue);
                boolean isInvalid = (boolean) responseMap.get("error");

                if (isInvalid){
                    /** 不合法, 重定向到登陆页面 */
                    System.out.println("不合法, 重定向到登陆页面");
                    response.sendRedirect(this.SSOLoginPage + "?setCookieURL=" + request.getScheme() + "://"
                            + request.getServerName() + ":" + request.getServerPort()
                            + path + "/setCookie&gotoURL=" + url);
                }else {

                    chain.doFilter(request, response);
                }
            }
        }
    }


    /**
     * 带着ticket去SSO认证
     * @param cookieValue
     * @return
     * @throws IOException
     */
    private Map<String, Object> SSOAuthCookieService(String cookieValue) throws IOException {
        String authAction = "?action=authCookie&cookieValue=";
        HttpClient httpClient = new HttpClient();
        GetMethod httpGet = new GetMethod(this.SSOServiceURL + authAction + cookieValue);
        try {
            httpClient.executeMethod(httpGet);
            /**
             * 解析返回值
             */
            System.out.println("response "+httpGet.getResponseBodyAsString());
            JSONObject jsonObject = JSONObject.parseObject(httpGet.getResponseBodyAsString());

            Map<String, Object> response = new HashMap<>();

            boolean isError = (boolean) jsonObject.get("error");
            response.put("error", jsonObject.get("error"));
            if (isError){
                /**
                 * 验证失败
                 */
                response.put("errorInfo", jsonObject.get("errorInfo"));
            } else {
                response.put("email", jsonObject.get("email"));
                response.put("userId", jsonObject.get("userId"));
            }
            return response;
        } finally {
            httpGet.releaseConnection();
        }
    }


    @Override
    public void destroy() {

    }

    private String getCookieValue(HttpServletRequest request){
        String cookieValue = "";
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (int i = 0; i < cookies.length; i++) {
                if (cookies[i].getName().equals(this.cookieName)) {
                    cookieValue = cookies[i].getValue();
                    System.out.println("found cookies");
                    break;
                }
            }
        }
        return cookieValue;
    }
//
//    private void logoutService(String cookieValue) throws IOException {
//        String authAction = "?action=logout&cookieName=";
//        HttpClient httpClient = new HttpClient();
//        GetMethod httpGet = new GetMethod(this.SSOServiceURL + authAction + cookieValue);
//        try {
//            httpClient.executeMethod(httpGet);
//            httpGet.getResponseBodyAsString();
//        } finally {
//            httpGet.releaseConnection();
//        }
//    }
}