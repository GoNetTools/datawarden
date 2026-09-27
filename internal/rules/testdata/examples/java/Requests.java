// Examples for the JVM web request sources (internal/rules/builtin/requests.yaml).
package examples;

import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;

class Requests {
    private static final Logger log = LoggerFactory.getLogger(Requests.class);

    // ruleid: src.jvm.spring_request_body
    void create(@RequestBody Map<String, Object> body, @RequestParam("page") String page) {
        // ruleid: log.jvm.logger
        log.info("signup {}", body);
        // ok: src.jvm.spring_request_body
        log.info("page {}", page);
    }

    void servlet(HttpServletRequest req, String field) {
        // ruleid: src.jvm.servlet_request, log.jvm.logger
        log.info("field {}", req.getParameter(field));
        // ok: src.jvm.servlet_request
        log.info("page {}", req.getParameter("page"));
    }
}
