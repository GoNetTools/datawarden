// Frontend conformance programs for Kotlin. Every language implements the
// same scenarios (see TestFrontendConformance in internal/app).
package conformance

class User(val id: Long, val email: String) {
    var contact: String = ""

    fun contactEmail(): String = email
}

data class Profile(val email: String, val nickname: String)

// scenario: param
fun param(email: String) {
    // ruleid: log.jvm.stdout
    println(email)
}

// scenario: local
fun local(email: String) {
    val x = email
    // ruleid: log.jvm.stdout
    println(x)
}

// scenario: concat
fun concat(email: String) {
    val msg = "signup $email"
    // ruleid: log.jvm.stdout
    println(msg)
}

// scenario: field
fun field(u: User) {
    // ruleid: log.jvm.stdout
    println(u.email)
}

// scenario: getter
fun getter(u: User) {
    // ruleid: log.jvm.stdout
    println(u.contactEmail())
}

// scenario: key
fun key(value: String) {
    val payload = mapOf("email" to value)
    // ruleid: log.jvm.stdout
    println(payload)
}

fun logIt(v: String) {
    // ruleid: log.jvm.stdout
    println(v)
}

// scenario: call-arg
fun callArg(email: String) {
    logIt(email)
}

fun normalize(s: String): String = s.trim().lowercase()

// scenario: call-return
fun callReturn(email: String) {
    // ruleid: log.jvm.stdout
    println(normalize(email))
}

// scenario: closure
fun closure(email: String, items: List<String>) {
    items.forEach {
        // ruleid: log.jvm.stdout
        println("$it $email")
    }
}

// scenario: field-store
fun fieldStore(phoneNumber: String) {
    val u = User(1, "")
    u.contact = phoneNumber
    // ruleid: log.jvm.stdout
    println(u.contact)
}

// scenario: collection
fun collection(email: String) {
    val xs = mutableListOf<String>()
    xs.add(email)
    // ruleid: log.jvm.stdout
    println(xs)
}

// scenario: object
fun whole(p: Profile) {
    // ruleid: log.jvm.stdout
    println(p)
}

fun maskEmail(e: String): String = e.take(1) + "***"

// scenario: masked
fun masked(email: String) {
    // ok: log.jvm.stdout
    println(maskEmail(email))
}

// scenario: not-pii
fun notPii(u: User, orderId: Long, count: Int) {
    // ok: log.jvm.stdout
    println("${u.id} $orderId $count")
}

// scenario: negative-context
fun negativeContext(phoneCount: Int, emailTemplate: String) {
    // ok: log.jvm.stdout
    println("$phoneCount $emailTemplate")
}

// scenario: overwritten
fun overwritten(email: String) {
    var x = email
    x = "anonymous"
    // ok: log.jvm.stdout
    println(x)
}

// scenario: remasked
fun remasked(email: String) {
    var userEmail = email
    userEmail = maskEmail(userEmail)
    // ok: log.jvm.stdout
    println(userEmail)
}

// scenario: branch-merge
fun branchMerge(email: String, verbose: Boolean) {
    var x = "anonymous"
    if (verbose) {
        x = email
    }
    // ruleid: log.jvm.stdout
    println(x)
}

// scenario: loop-carried
fun loopCarried(email: String, items: List<String>) {
    var x = "anonymous"
    for (item in items) {
        // ruleid: log.jvm.stdout
        println(x)
        x = email
    }
}
