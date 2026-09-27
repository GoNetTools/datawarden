// Examples for the Kotlin web request sources (internal/rules/builtin/requests.yaml).
package examples.requests

import org.slf4j.LoggerFactory
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestParam

class SignupController {
    private val log = LoggerFactory.getLogger(SignupController::class.java)

    // ruleid: src.jvm.spring_request_body
    fun create(@RequestBody body: Map<String, Any>, @RequestParam("page") page: String) {
        // ruleid: log.jvm.logger
        log.info("signup {}", body)
        // ok: src.jvm.spring_request_body
        log.info("page {}", page)
    }
}
