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

import stapl.examples.policies.EhealthPolicy
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
import stapl.core.ConcreteLogObligationAction

object EhealthPolicyTest {

  @BeforeClass def setup() {
    // nothing to do
  }
}
/**
 * Correctness tests of the e-health policy.
 */
class EhealthPolicyTest extends AssertionsForJUnit {

  import EhealthPolicy._
  // set up the PDP, use an empty attribute finder since we will provide all attributes in the request
  //val pdp = new PDP(javaLikePolicy, new AttributeFinder)
  val pdp = new PDP(naturalPolicy, new AttributeFinder)

  @Before def setup() {
    // nothing to do
  }

  @Test def testNotApplicableOtherAction() {
    val Result(decision, obligationActions, employedAttributes) = pdp.evaluate("maarten", "an-action", "doc123")
    assert(decision === NotApplicable)
    assert(obligationActions == List())
    // ignore the employed attributes for now
  }

  @Test def testDenyWithdrawnConsents() {
    val Result(decision, obligationActions, employedAttributes) = pdp.evaluate("maarten", "view", "doc123",
      subject.roles -> List("medical_personnel"),
      subject.triggered_breaking_glass -> false,
      resource.type_ -> "patientstatus",
      resource.owner_withdrawn_consents -> List("subject1", "subject2", "subject3", "maarten"))
    assert(decision === Deny)
    assert(obligationActions == List())
    // ignore the employed attributes for now
  }

  @Test def testDenyIncorrectMedicalPersonnel() {
    val Result(decision, obligationActions, employedAttributes) = pdp.evaluate("maarten", "view", "doc123",
      subject.roles -> List("medical_personnel", "role-not-allowed"),
      subject.triggered_breaking_glass -> false,
      resource.type_ -> "patientstatus",
      resource.owner_withdrawn_consents -> List("subject1", "subject2", "subject3", "maarten"))
    assert(decision === Deny)
    assert(obligationActions == List())
    // ignore the employed attributes for now
  }

  @Test def testPhysicianDepartment1() {
    val Result(decision, obligationActions, employedAttributes) = pdp.evaluate("maarten", "view", "doc123",
      subject.roles -> List("medical_personnel", "physician"),
      subject.triggered_breaking_glass -> false,
      subject.department -> "department-not-allowed",
      resource.type_ -> "patientstatus",
      resource.owner_withdrawn_consents -> List("subject1", "subject2", "subject3", "maarten"))
    assert(decision === Deny)
    assert(obligationActions == List())
    // ignore the employed attributes for now
  }

  @Test def testPhysicianDepartment2() {
    val Result(decision, obligationActions, employedAttributes) = pdp.evaluate("maarten", "view", "doc123",
      subject.roles -> List("medical_personnel", "physician"),
      subject.triggered_breaking_glass -> true,
      subject.department -> "cardiology",
      resource.type_ -> "patientstatus",
      resource.owner_withdrawn_consents -> List("subject1", "subject2", "subject3", "maarten"))
    assert(decision === Permit)
    // ignore the obligation actions and employed attributes for now
  }

  @Test def testPhysicianDepartment3() {
    val Result(decision, obligationActions, employedAttributes) = pdp.evaluate("maarten", "view", "doc123",
      subject.roles -> List("medical_personnel", "physician"),
      subject.triggered_breaking_glass -> true,
      subject.department -> "elder_care",
      resource.type_ -> "patientstatus",
      resource.owner_withdrawn_consents -> List("subject1", "subject2", "subject3", "maarten"))
    assert(decision === Permit)
    // ignore the obligation actions and employed attributes for now
  }

  @Test def testPhysicianDepartment4() {
    val Result(decision, obligationActions, employedAttributes) = pdp.evaluate("maarten", "view", "doc123",
      subject.roles -> List("medical_personnel", "physician"),
      subject.triggered_breaking_glass -> true,
      subject.department -> "emergency",
      resource.type_ -> "patientstatus",
      resource.owner_withdrawn_consents -> List("subject1", "subject2", "subject3", "maarten"))
    assert(decision === Permit)
    // ignore the obligation actions and employed attributes for now
  }

  @Test def testPermitPhysicianEmergency1() {
    val Result(decision, obligationActions, employedAttributes) = pdp.evaluate("maarten", "view", "doc123",
      subject.roles -> List("medical_personnel", "physician"),
      subject.triggered_breaking_glass -> true,
      subject.department -> "cardiology",
      resource.type_ -> "patientstatus",
      resource.owner_withdrawn_consents -> List("subject1", "subject2", "subject3"))
    assert(decision === Permit)
    assert(obligationActions == List(
      ConcreteLogObligationAction("maarten performed breaking-the-glass procedure"),
      ConcreteLogObligationAction("permit because of breaking-the-glass procedure")))
    // ignore the employed attributes for now
  }

  @Test def testPermitPhysicianEmergency2() {
    val Result(decision, obligationActions, employedAttributes) = pdp.evaluate("maarten", "view", "doc123",
      subject.roles -> List("medical_personnel", "physician"),
      subject.triggered_breaking_glass -> false,
      subject.department -> "cardiology",
      resource.type_ -> "patientstatus",
      resource.owner_withdrawn_consents -> List("subject1", "subject2", "subject3"),
      resource.operator_triggered_emergency -> true)
     assert(decision === Permit)
     assert(obligationActions == List())
     // ignore the employed attributes for now
  }

  @Test def testPermitPhysicianEmergency3() {
    val Result(decision, obligationActions, employedAttributes) = pdp.evaluate("maarten", "view", "doc123",
      subject.roles -> List("medical_personnel", "physician"),
      subject.triggered_breaking_glass -> false,
      subject.department -> "cardiology",
      resource.type_ -> "patientstatus",
      resource.owner_withdrawn_consents -> List("subject1", "subject2", "subject3"),
      resource.operator_triggered_emergency -> false,
      resource.indicates_emergency -> true)
     assert(decision === Permit)
     assert(obligationActions == List())
     // ignore the employed attributes for now
  }

  @Test def testOverrideWithdrawnConsents {
    val Result(decision, obligationActions, employedAttributes) = pdp.evaluate("maarten", "view", "doc123",
      subject.roles -> List("medical_personnel", "physician"),
      subject.triggered_breaking_glass -> true,
      subject.department -> "cardiology",
      resource.type_ -> "patientstatus",
      resource.owner_withdrawn_consents -> List("subject1", "subject2", "subject3", "maarten"))
     assert(decision === Permit)
     assert(obligationActions == List(
        ConcreteLogObligationAction("maarten performed breaking-the-glass procedure"),
        ConcreteLogObligationAction("permit because of breaking-the-glass procedure")))
     // ignore the employed attributes for now
  }

  @Test def testPermitNurseOfElderCareDepartment {
    val Result(decision, obligationActions, employedAttributes) = pdp.evaluate("maarten", "view", "doc123",
      subject.roles -> List("medical_personnel", "nurse"),
      subject.triggered_breaking_glass -> false,
      subject.department -> "elder_care",
      subject.allowed_to_access_pms -> true,
      subject.shift_start -> new LocalDateTime(2014, 6, 24, 9, 0, 0),
      subject.shift_stop -> new LocalDateTime(2014, 6, 24, 17, 0, 0),
      subject.location -> "hospital",
      subject.admitted_patients_in_nurse_unit -> List("patientX", "patientY"),
      subject.responsible_patients -> List("patientX", "patientZ"),
      resource.owner_id -> "patientX",
      resource.owner_withdrawn_consents -> List("subject1"),
      resource.type_ -> "patientstatus",
      resource.created -> new LocalDateTime(2014, 6, 22, 14, 2, 1), // three days ago
      environment.currentDateTime -> new LocalDateTime(2014, 6, 24, 14, 2, 1))
     assert(decision === Permit)
     assert(obligationActions == List())
     // ignore the employed attributes for now
  }

  @Test def testDenyNurseOfElderCareDepartmentNotAllowed {
    val Result(decision, obligationActions, employedAttributes) = pdp.evaluate("maarten", "view", "doc123",
      subject.roles -> List("medical_personnel", "nurse"),
      subject.triggered_breaking_glass -> false,
      subject.department -> "elder_care",
      subject.allowed_to_access_pms -> false, // X
      subject.shift_start -> new LocalDateTime(2014, 6, 24, 9, 0, 0),
      subject.shift_stop -> new LocalDateTime(2014, 6, 24, 17, 0, 0),
      subject.location -> "hospital",
      subject.admitted_patients_in_nurse_unit -> List("patientX", "patientY"),
      subject.responsible_patients -> List("patientX", "patientZ"),
      resource.owner_id -> "patientX",
      resource.owner_withdrawn_consents -> List("subject1"),
      resource.type_ -> "patientstatus",
      resource.created -> new LocalDateTime(2014, 6, 22, 14, 2, 1), // three days ago
      environment.currentDateTime -> new LocalDateTime(2014, 6, 24, 14, 2, 1))
     assert(decision === Deny)
     assert(obligationActions == List())
     // ignore the employed attributes for now
  }

  @Test def testDenyNurseOfElderCareDepartmentNotAtHospital {
    val Result(decision, obligationActions, employedAttributes) = pdp.evaluate("maarten", "view", "doc123",
      subject.roles -> List("medical_personnel", "nurse"),
      subject.triggered_breaking_glass -> false,
      subject.department -> "elder_care",
      subject.allowed_to_access_pms -> true,
      subject.shift_start -> new LocalDateTime(2014, 6, 24, 9, 0, 0),
      subject.shift_stop -> new LocalDateTime(2014, 6, 24, 17, 0, 0),
      subject.location -> "somewhere-not-the-hospital", // X
      subject.admitted_patients_in_nurse_unit -> List("patientX", "patientY"),
      subject.responsible_patients -> List("patientX", "patientZ"),
      resource.owner_id -> "patientX",
      resource.owner_withdrawn_consents -> List("subject1"),
      resource.type_ -> "patientstatus",
      resource.created -> new LocalDateTime(2014, 6, 22, 14, 2, 1), // three days ago
      environment.currentDateTime -> new LocalDateTime(2014, 6, 24, 14, 2, 1))
     assert(decision === Deny)
     assert(obligationActions == List())
     // ignore the employed attributes for now
  }

  @Test def testDenyNurseOfElderCareDepartmentNotInNurseUnit {
    val Result(decision, obligationActions, employedAttributes) = pdp.evaluate("maarten", "view", "doc123",
      subject.roles -> List("medical_personnel", "nurse"),
      subject.triggered_breaking_glass -> false,
      subject.department -> "elder_care",
      subject.allowed_to_access_pms -> true,
      subject.shift_start -> new LocalDateTime(2014, 6, 24, 9, 0, 0),
      subject.shift_stop -> new LocalDateTime(2014, 6, 24, 17, 0, 0),
      subject.location -> "hospital",
      subject.admitted_patients_in_nurse_unit -> List("patientZ", "patientY"), // X 
      subject.responsible_patients -> List("patientX", "patientZ"),
      resource.owner_id -> "patientX",
      resource.owner_withdrawn_consents -> List("subject1"),
      resource.type_ -> "patientstatus",
      resource.created -> new LocalDateTime(2014, 6, 22, 14, 2, 1), // three days ago
      environment.currentDateTime -> new LocalDateTime(2014, 6, 24, 14, 2, 1))
     assert(decision === Deny)
     assert(obligationActions == List())
     // ignore the employed attributes for now
  }

  @Test def testDenyNurseOfElderCareDepartmentNotResponsible {
    val Result(decision, obligationActions, employedAttributes) = pdp.evaluate("maarten", "view", "doc123",
      subject.roles -> List("medical_personnel", "nurse"),
      subject.triggered_breaking_glass -> false,
      subject.department -> "elder_care",
      subject.allowed_to_access_pms -> true,
      subject.shift_start -> new LocalDateTime(2014, 6, 24, 9, 0, 0),
      subject.shift_stop -> new LocalDateTime(2014, 6, 24, 17, 0, 0),
      subject.location -> "hospital",
      subject.admitted_patients_in_nurse_unit -> List("patientX", "patientY"),
      subject.responsible_patients -> List("patientY", "patientZ"),
      resource.owner_id -> "patientX",
      resource.owner_withdrawn_consents -> List("subject1"),
      resource.type_ -> "patientstatus",
      resource.created -> new LocalDateTime(2014, 6, 22, 14, 2, 1), // three days ago
      environment.currentDateTime -> new LocalDateTime(2014, 6, 24, 14, 2, 1))
     assert(decision === Deny)
     assert(obligationActions == List())
     // ignore the employed attributes for now
  }

  @Test def testDenyNurseOfElderCareDepartmentNotOwner {
    val Result(decision, obligationActions, employedAttributes) = pdp.evaluate("maarten", "view", "doc123",
      subject.roles -> List("medical_personnel", "nurse"),
      subject.triggered_breaking_glass -> false,
      subject.department -> "elder_care",
      subject.allowed_to_access_pms -> true,
      subject.shift_start -> new LocalDateTime(2014, 6, 24, 9, 0, 0),
      subject.shift_stop -> new LocalDateTime(2014, 6, 24, 17, 0, 0),
      subject.location -> "hospital",
      subject.admitted_patients_in_nurse_unit -> List("patientX", "patientY"),
      subject.responsible_patients -> List("patientX", "patientZ"),
      resource.owner_id -> "patientA",
      resource.owner_withdrawn_consents -> List("subject1"),
      resource.type_ -> "patientstatus",
      resource.created -> new LocalDateTime(2014, 6, 22, 14, 2, 1), // three days ago
      environment.currentDateTime -> new LocalDateTime(2014, 6, 24, 14, 2, 1))
     assert(decision === Deny)
     assert(obligationActions == List())
     // ignore the employed attributes for now
  }

  @Test def testDenyNurseOfElderCareDepartmentTooLongAgo {
    val Result(decision, obligationActions, employedAttributes) = pdp.evaluate("maarten", "view", "doc123",
      subject.roles -> List("medical_personnel", "nurse"),
      subject.triggered_breaking_glass -> false,
      subject.department -> "elder_care",
      subject.allowed_to_access_pms -> true,
      subject.shift_start -> new LocalDateTime(2014, 6, 24, 9, 0, 0),
      subject.shift_stop -> new LocalDateTime(2014, 6, 24, 17, 0, 0),
      subject.location -> "hospital",
      subject.admitted_patients_in_nurse_unit -> List("patientX", "patientY"),
      subject.responsible_patients -> List("patientX", "patientZ"),
      resource.owner_id -> "patientX",
      resource.owner_withdrawn_consents -> List("subject1"),
      resource.type_ -> "patientstatus",
      resource.created -> new LocalDateTime(2014, 6, 1, 14, 2, 1), // X more than five days ago
      environment.currentDateTime -> new LocalDateTime(2014, 6, 24, 14, 2, 1))
     assert(decision === Deny)
     assert(obligationActions == List())
     // ignore the employed attributes for now
  }
}
