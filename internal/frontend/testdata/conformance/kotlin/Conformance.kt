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

// scenario: mutated-later
fun mutatedLater(email: String) {
    val xs = mutableListOf<String>()
    // ok: log.jvm.stdout
    println(xs)
    xs.add(email)
}

// scenario: early-return
fun earlyReturn(email: String, invalid: Boolean) {
    var x = "anonymous"
    if (invalid) {
        x = email
        // ruleid: log.jvm.stdout
        println(x)
        return
    }
    // ok: log.jvm.stdout
    println(x)
}

// scenario: break-exit
fun breakExit(email: String, items: List<String>) {
    var x = "anonymous"
    for (item in items) {
        if (item.isEmpty()) {
            x = email
            break
        }
    }
    // ruleid: log.jvm.stdout
    println(x)
}

// scenario: continue-skip
fun continueSkip(email: String, items: List<String>) {
    for (item in items) {
        var x = "anonymous"
        if (item.isEmpty()) {
            x = email
            continue
        }
        // ok: log.jvm.stdout
        println(x)
    }
}

// scenario: snapshot
fun snapshot(email: String) {
    val items = mutableListOf<String>()
    val msg = "items=$items"
    items.add(email)
    // ok: log.jvm.stdout
    println(msg)
}

object LogConfig {
    const val VERBOSE = false
}

// scenario: constant-condition
fun constantCondition(email: String) {
    if (LogConfig.VERBOSE) {
        // ok: log.jvm.stdout
        println(email)
    }
}

// scenario: field-across-methods
class Mailbox(private val addr: String) {
    fun announce() {
        // ruleid: log.jvm.stdout
        println("sending to $addr")
    }
}

fun fieldAcrossMethods(email: String) = Mailbox(email).announce()

// scenario: dynamic-dispatch
interface Channel {
    fun deliver(to: String)
}

class SmsChannel : Channel {
    override fun deliver(to: String) {
        // ruleid: log.jvm.stdout
        println("sms $to")
    }
}

fun dynamicDispatch(c: Channel, email: String) = c.deliver(email)

// scenario: exception
fun exception(email: String) {
    try {
        throw IllegalArgumentException("unknown user $email")
    } catch (e: IllegalArgumentException) {
        // ruleid: log.jvm.stdout
        println(e.message)
    }
}

// scenario: lambda-variable
fun lambdaVariable(email: String) {
    val show = { v: String ->
        // ruleid: log.jvm.stdout
        println(v)
    }
    show(email)
}

// scenario: consent-guard
interface Consents {
    fun hasConsent(): Boolean
}

fun consentGuard(email: String, consents: Consents) {
    if (!consents.hasConsent()) return
    // Reported with the consent check that guards it.
    // ruleid: log.jvm.stdout
    println(email)
}

// scenario: nested-field
class Note(var text: String = "")

class Folder(val note: Note = Note())

fun nestedField(email: String) {
    val f = Folder()
    f.note.text = email
    // ruleid: log.jvm.stdout
    println(f.note.text)
}

// scenario: closure-assign
fun closureAssign(email: String, items: List<String>) {
    var found = ""
    items.forEach { found = email }
    // ruleid: log.jvm.stdout
    println(found)
}

// scenario: callback-before-mutation
fun callbackBeforeMutation(email: String, items: List<String>) {
    val xs = mutableListOf<String>()
    items.forEach {
        // forEach runs the lambda before the add below.
        // ok: log.jvm.stdout
        println(xs)
    }
    xs.add(email)
}

// scenario: closure-field
class Notifier(private val onSend: (String) -> Unit) {
    fun send(v: String) {
        onSend(v)
    }
}

fun closureField(email: String) {
    val n = Notifier { v ->
        // ruleid: log.jvm.stdout
        println(v)
    }
    n.send(email)
}

// scenario: closure-collection
class EventBus {
    private val handlers = mutableListOf<(String) -> Unit>()

    fun subscribe(h: (String) -> Unit) {
        handlers.add(h)
    }

    fun publish(v: String) {
        for (h in handlers) h(v)
    }
}

fun closureCollection(email: String) {
    val bus = EventBus()
    bus.subscribe { v ->
        // ruleid: log.jvm.stdout
        println(v)
    }
    bus.publish(email)
}

// scenario: closure-return
fun makePrinter(): (String) -> Unit = { v ->
    // ruleid: log.jvm.stdout
    println(v)
}

fun closureReturn(email: String) {
    val printer = makePrinter()
    printer(email)
}

// scenario: consent-helper
fun mayContact(consents: Consents): Boolean = consents.hasConsent()

fun consentHelper(email: String, consents: Consents) {
    if (mayContact(consents)) {
        // ruleid: log.jvm.stdout
        println(email)
    }
}

// scenario: consent-caller
fun consentedSend(email: String) {
    // Only ever called after a consent check: reported with it.
    // ruleid: log.jvm.stdout
    println(email)
}

fun consentCaller(email: String, consents: Consents) {
    if (consents.hasConsent()) consentedSend(email)
}

// scenario: validation-check
fun isValidEmail(s: String): Boolean = s.contains("@")

fun validationCheck(input: String) {
    if (isValidEmail(input)) {
        // ruleid: log.jvm.stdout
        println(input)
    }
}

// scenario: sanitizer-check
fun isMasked(s: String): Boolean = s.startsWith("***")

fun sanitizerCheck(email: String) {
    if (isMasked(email)) {
        // ok: log.jvm.stdout
        println(email)
    }
}

// scenario: alias
class Card {
    var holder = ""
}

fun aliasStore(email: String) {
    val a = Card()
    val b = a
    b.holder = email
    // ruleid: log.jvm.stdout
    println(a.holder)
}
