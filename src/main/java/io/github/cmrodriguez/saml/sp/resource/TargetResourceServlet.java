package io.github.cmrodriguez.saml.sp.resource;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * This is the resource that the access filter is protecting
 */
public class TargetResourceServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		resp.setContentType("text/html");
		resp.getWriter().append("<h1>You are now at the requested resource</h1>");
		resp.getWriter().append("This is the protected resource. You are authenticated");
	}
}
