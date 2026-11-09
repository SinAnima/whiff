<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="org.saltmere.harbour.TideTable" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%-- Saltmere tide page --%>
<jsp:useBean id="tides" class="org.saltmere.harbour.TideTable" scope="request"/>
<html><body>
<h1>Saltmere tides</h1>
<c:forEach var="t" items="${tides.today}"><p>${t.kind} at ${t.time}</p></c:forEach>
</body></html>
