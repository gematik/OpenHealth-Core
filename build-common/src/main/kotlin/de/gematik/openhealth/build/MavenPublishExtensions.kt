/*
 * Copyright 2025 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.openhealth.build

import com.vanniktech.maven.publish.MavenPublishBaseExtension
import com.vanniktech.maven.publish.SonatypeHost

fun MavenPublishBaseExtension.applyOpenHealthMavenPublishing(
    artifactId: String,
    name: String,
    description: String,
    inceptionYear: String,
    githubUrl: String = "https://github.com/gematik/OpenHealth-Core",
) {
//    publishToMavenCentral(System.getenv("SERVER_NEXUS_GEMATIK_SNAPSHOT_REPOSITORY")!!)
    publishToMavenCentral(SonatypeHost.DEFAULT)

    // signAllPublications()

    coordinates(artifactId = artifactId)

    pom { pom ->
        pom.name.set(name)
        pom.description.set(description)
        pom.inceptionYear.set(inceptionYear)
        pom.url.set(githubUrl)
        pom.licenses { licenses ->
            licenses.license { license ->
                license.name.set("Apache 2.0")
                license.url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                license.distribution.set("repo")
            }
        }
        pom.developers { developers ->
            developers.developer { developer ->
                developer.name.set("gematik GmbH")
                developer.url.set("https://github.com/gematik")
            }
        }
        pom.scm { scm ->
            scm.url.set(githubUrl)
            scm.connection.set("scm:git:$githubUrl.git")
            scm.developerConnection.set("scm:git:$githubUrl.git")
        }
    }
}