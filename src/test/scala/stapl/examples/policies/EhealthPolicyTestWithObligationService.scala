/**
 *    Copyright 2014 KU Leuven Research and Developement - iMinds - Distrinet
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 *
 *    Administrative Contact: dnet-project-office@cs.kuleuven.be
 *    Technical Contact: maarten.decat@cs.kuleuven.be
 *    Author: maarten.decat@cs.kuleuven.be
 */
package stapl.examples.policies

import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import stapl.core.pdp.PDP
import stapl.core.pdp.AttributeFinder
import stapl.core.pdp.RequestCtx
import org.junit.Assert._
import org.scalatest.junit.AssertionsForJUnit
import org.joda.time.LocalDateTime
import EhealthPolicy.environment
import EhealthPolicy.naturalPolicy
import EhealthPolicy.resource
import EhealthPolicy.subject
import stapl.core.Result
import stapl.core.NotApplicable
import stapl.core.Deny
import stapl.core.Permit
import stapl.core.dsl.log
import stapl.core.pdp.ObligationService
import stapl.core.pdp.LogObligationServiceModule
import stapl.core.ConcreteLogObligationAction

object EhealthPolicyTestWithObligationService {

  @BeforeClass def setup() {
    // nothing to do
  }
}
/**
 * Correctness tests of the e-health policy.
 */
class EhealthPolicyTestWithObligationService extends AssertionsForJUnit {

  import EhealthPolicy._

  @Before def setup() {
    // nothing to do
  }

  @Test def testWithObligationService() {
    val obligationService = new ObligationService
    obligationService += new LogObligationServiceModule
    val pdp = new PDP(naturalPolicy, new AttributeFinder, obligationService)
    val result = pdp.evaluate("maarten", "view", "doc123",
      subject.roles -> List("medical_personnel", "physician"),
      subject.triggered_breaking_glass -> true,
      subject.department -> "cardiology",
      resource.type_ -> "patientstatus",
      resource.owner_withdrawn_consents -> List("subject1", "subject2", "subject3", "maarten"))
    assertEquals(List(), result.obligationActions)
  }

  @Test def testWithoutObligationService() {
    val pdp = new PDP(naturalPolicy)
    val result = pdp.evaluate("maarten", "view", "doc123",
      subject.roles -> List("medical_personnel", "physician"),
      subject.triggered_breaking_glass -> true,
      subject.department -> "cardiology",
      resource.type_ -> "patientstatus",
      resource.owner_withdrawn_consents -> List("subject1", "subject2", "subject3", "maarten"))
    assertEquals(List(
      ConcreteLogObligationAction("maarten performed breaking-the-glass procedure"),
      ConcreteLogObligationAction("permit because of breaking-the-glass procedure")), result.obligationActions)
  }
}