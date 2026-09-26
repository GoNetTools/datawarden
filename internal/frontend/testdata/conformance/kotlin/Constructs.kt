// Language constructs the Kotlin frontend must lower. Unlike the shared
// scenarios in Conformance.kt, these are specific to Kotlin.
package conformance

object Session {
    var lastEmail: String = ""
}

class Mailer {
    companion object {
        fun send(to: String) {
            // ruleid: log.jvm.stdout
            println("mail to $to")
        }
    }
}

fun String.shout(): String = uppercase()

fun ifElse(email: String, verbose: Boolean) {
    if (verbose) {
        // ruleid: log.jvm.stdout
        println("verbose $email")
    } else {
        // ok: log.jvm.stdout
        println("quiet")
    }
}

fun whenExpr(email: String, kind: Int) {
    val label = when (kind) {
        1 -> email
        else -> "none"
    }
    // ruleid: log.jvm.stdout
    println(label)
}

fun loops(emails: List<String>) {
    for (e in emails) {
        // ruleid: log.jvm.stdout
        println(e)
    }
    var i = 0
    while (i < emails.size) {
        // ruleid: log.jvm.stdout
        println(emails[i])
        i++
    }
}

fun tryCatch(email: String) {
    try {
        Mailer.send(email)
    } catch (e: Exception) {
        // ruleid: log.jvm.stdout
        println("failed for $email")
    }
}

fun elvisAndSafeCall(email: String?, profile: Profile?) {
    val e = email ?: "none"
    // ruleid: log.jvm.stdout
    println(e)
    profile?.email?.let {
        // ruleid: log.jvm.stdout
        println(it)
    }
}

fun scopeFunctions(email: String) {
    val msg = StringBuilder().apply { append(email) }.toString()
    // ruleid: log.jvm.stdout
    println(msg)
}

fun objectState(email: String) {
    Session.lastEmail = email
    // ruleid: log.jvm.stdout
    println(Session.lastEmail)
}

fun extension(email: String) {
    // ruleid: log.jvm.stdout
    println(email.shout())
}

fun namedArgs(email: String) {
    // ruleid: log.jvm.stdout
    println(message = email)
}

fun destructuring(profile: Profile) {
    val (mail, _) = profile
    // ruleid: log.jvm.stdout
    println(mail)
}

fun lambdaValue(email: String) {
    val printer: (String) -> Unit = {
        // Called through the printer variable below.
        // ruleid: log.jvm.stdout
        println(it)
    }
    printer(email)
}

fun whenOverwrites(email: String, kind: Int) {
    var x = email
    when (kind) {
        1 -> x = "one"
        else -> x = "other"
    }
    // ok: log.jvm.stdout
    println(x)
}

fun whenPartial(email: String, kind: Int) {
    var x = "anonymous"
    when (kind) {
        1 -> x = email
    }
    // ruleid: log.jvm.stdout
    println(x)
}

fun catchSeesEarlierValue(email: String) {
    var x = email
    try {
        x = "cleared"
        x.toInt()
    } catch (e: NumberFormatException) {
        // ruleid: log.jvm.stdout
        println(x)
    }
}

fun callbackRunsLater(email: String, handlers: MutableList<() -> Unit>) {
    val xs = mutableListOf<String>()
    handlers.add {
        // A lambda may run after the add below.
        // ruleid: log.jvm.stdout
        println(xs)
    }
    xs.add(email)
}

fun labeledBreak(email: String, rows: List<List<String>>) {
    var x = "anonymous"
    outer@ for (row in rows) {
        for (cell in row) {
            if (cell.isEmpty()) {
                x = email
                break@outer
            }
        }
        x = "reset"
    }
    // ruleid: log.jvm.stdout
    println(x)
}

fun whileTrue(email: String) {
    var x = email
    while (true) {
        x = "cleared"
        break
    }
    // ok: log.jvm.stdout
    println(x)
}

class Profile(private val mail: String) {
    val contact: String
        get() = mail
}

fun customGetter(email: String) {
    // ruleid: log.jvm.stdout
    println(Profile(email).contact)
}

data class Ticket(val id: Long, val note: String, val owner: String)

fun namedArguments(email: String) {
    val t = Ticket(owner = "system", note = email, id = 1)
    // ruleid: log.jvm.stdout
    println(t.note)
    // ok: log.jvm.stdout
    println(t.owner)
}

class Dispatcher {
    fun send(to: String) {
        // ruleid: log.jvm.stdout
        println("dispatch $to")
    }
}

fun callableReference(email: String) {
    Dispatcher::send.call(Dispatcher(), email)
}

fun reflectiveProperty(t: Ticket) {
    val prop = Ticket::owner
    // ok: log.jvm.stdout
    println(prop.get(t))
}

// Current Kotlin syntax the previous grammar could not read (#44). Each
// construct is followed by a flow, so the code around it must be lowered.
fun interface Sender {
    fun send(to: String)
}

class Stats {
    var trackedEmail: String = ""
}

class Holder(private val stats: Stats) {
    fun get(): Stats = stats
}

fun assignToPropertyOfCallResult(holder: Holder, email: String) {
    holder.get().trackedEmail = email
    // ruleid: log.jvm.stdout
    println(holder.get().trackedEmail)
}

fun whenWithInAndTrailingComma(email: String, known: List<String>, kind: Int) {
    when (email) {
        in known -> println("known")
        else -> {
            // ruleid: log.jvm.stdout
            println(email)
        }
    }
    when (kind) {
        1,
        2,
        -> println("small")
        else -> {
            // ruleid: log.jvm.stdout
            println(email)
        }
    }
}

fun qualifiedReceiverType(block: StringBuilder.() -> Unit, email: String) {
    // ruleid: log.jvm.stdout
    println(email)
}

fun safeCastOnNextLine(value: Any, email: String) {
    val text = value
        .toString()
        as? String
        ?: return
    // ruleid: log.jvm.stdout
    println(text + email)
}

fun shortTemplate(email: String) {
    // "$name" in a one-line string is an interpolation of name.
    // ruleid: log.jvm.stdout
    println("sent to $email today")
    // ok: log.jvm.stdout
    println("costs $5")
}

fun consentNegatedCall(consents: Consents, email: String) {
    if (!consents.hasConsent()) {
        // ok: log.jvm.stdout
        println("no consent")
        return
    }
    // ruleid: log.jvm.stdout
    println(email)
}
