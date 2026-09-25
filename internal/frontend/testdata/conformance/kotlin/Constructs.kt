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
        // Known gap: calling a lambda through a variable does not connect
        // the argument to the lambda's parameter.
        // todoruleid: log.jvm.stdout
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
