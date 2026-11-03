
package com.example.androidsecuritydemo

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.example.androidsecuritydemo.ui.theme.AndroidSecurityDemoTheme

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            AndroidSecurityDemoTheme {
                SecurityScreen()
            }
        }
    }
}

@Composable
fun SecurityScreen() {

    val checks = listOf(
        "Application Debugging" to
                "Check whether debugging is enabled in release builds.",

        "Cleartext Traffic" to
                "Check whether insecure HTTP communication is permitted.",

        "Hardcoded Credentials" to
                "Inspect source code for fixed usernames and passwords.",

        "Weak Cryptography" to
                "Check for outdated encryption and hashing algorithms.",

        "Sensitive Data Storage" to
                "Inspect how passwords and sensitive information are stored."
    )

    var completed by remember {
        mutableStateOf(false)
    }

    Scaffold { innerPadding ->

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(20.dp)
        ) {

            Text(
                text = "Android Security Assessment",
                style = MaterialTheme.typography.headlineSmall
            )

            Spacer(modifier = Modifier.height(12.dp))

            Text(
                text = "Security Testing Demonstration",
                style = MaterialTheme.typography.titleMedium
            )

            Spacer(modifier = Modifier.height(16.dp))

            LazyColumn(
                modifier = Modifier.weight(1f)
            ) {

                items(checks) { check ->

                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 6.dp)
                    ) {

                        Column(
                            modifier = Modifier.padding(14.dp)
                        ) {

                            Text(
                                text = check.first,
                                style = MaterialTheme.typography.titleMedium
                            )

                            Spacer(modifier = Modifier.height(5.dp))

                            Text(text = check.second)
                        }
                    }
                }
            }

            Button(
                onClick = {
                    completed = true
                },
                modifier = Modifier.fillMaxWidth()
            ) {

                Text("Complete Demo Check")
            }

            if (completed) {

                Spacer(modifier = Modifier.height(12.dp))

                Text(
                    text = "Demo checklist completed! Manual security validation is still required.",
                    style = MaterialTheme.typography.bodyMedium
                )
            }
        }
    }
}
