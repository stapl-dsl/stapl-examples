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
package stapl.examples.templates

import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import stapl.core.pdp.PDP
import stapl.core.pdp.AttributeFinder
import stapl.core.pdp.RequestCtx
import org.junit.Assert._
import org.scalatest.junit.AssertionsForJUnit
import org.joda.time.LocalDateTime
import stapl.templates.rbac.Role
import stapl.core.Result
import stapl.core.NotApplicable
import stapl.core.Deny
import stapl.core.Permit
import stapl.core.log
import stapl.examples.templates.ehealth.ehealthPolicyWithoutTemplates
import stapl.examples.templates.ehealth.ehealthPolicyWithTemplates
import stapl.core.ConcreteLogObligationAction

class EhealthPolicyTest extends AssertionsForJUnit {

  import ehealthPolicyWithoutTemplates.{ policy, subject, action, resource, environment }
  val pdp = new PDP(policy)

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

/**
 * Correctness tests of templated version of the e-health policy.
 */
class EhealthPolicyTemplatesTest extends AssertionsForJUnit {

  val w = ehealthPolicyWithTemplates
  val wo = ehealthPolicyWithoutTemplates
  val pdpWith = new PDP(w.policy)
  val pdpWithout = new PDP(wo.policy)

  @Test def testNotApplicableOtherActionSame() {
    assert(
      pdpWith.evaluate("maarten", "an-action", "doc123")
        ===
        pdpWithout.evaluate("maarten", "an-action", "doc123"))
  }

  @Test def testDenyWithdrawnConsentsSame() {
    val resultWith = pdpWith.evaluate("maarten", "view", "doc123",
      w.subject.roles -> List(w.medical_personel),
      w.subject.triggered_breaking_glass -> false,
      w.resource.htype -> w.patientStatus,
      w.resource.owner_withdrawn_consents -> List("subject1", "subject2", "subject3", "maarten"))
    val resultWithout = pdpWithout.evaluate("maarten", "view", "doc123",
      wo.subject.roles -> List("medical_personnel"),
      wo.subject.triggered_breaking_glass -> false,
      wo.resource.type_ -> "patientstatus",
      wo.resource.owner_withdrawn_consents -> List("subject1", "subject2", "subject3", "maarten"))
    assert(resultWith.decision === resultWithout.decision)
    assert(resultWith.obligationActions === resultWithout.obligationActions)
    // ignore the employed attributes for now
  }

  @Test def testDenyIncorrectMedicalPersonnel() {
    val resultWith = pdpWith.evaluate("maarten", "view", "doc123",
      w.subject.roles -> List(w.medical_personel, Role("another type of personel", w.medical_personel)),
      w.subject.triggered_breaking_glass -> false,
      w.resource.htype -> w.patientStatus,
      w.resource.owner_withdrawn_consents -> List("subject1", "subject2", "subject3", "maarten"))
    val resultWithout = pdpWithout.evaluate("maarten", "view", "doc123",
      wo.subject.roles -> List("medical_personnel", "role-not-allowed"),
      wo.subject.triggered_breaking_glass -> false,
      wo.resource.type_ -> "patientstatus",
      wo.resource.owner_withdrawn_consents -> List("subject1", "subject2", "subject3", "maarten"))
    assert(resultWith.decision === resultWithout.decision)
    assert(resultWith.obligationActions === resultWithout.obligationActions)
    // ignore the employed attributes for now
  }

  @Test def testPhysicianDepartment1() {
    val resultWith = pdpWith.evaluate("maarten", "view", "doc123",
      w.subject.roles -> List(w.medical_personel, w.physician),
      w.subject.triggered_breaking_glass -> false,
      w.subject.department -> "department-not-allowed",
      w.resource.htype -> w.patientStatus,
      w.resource.owner_withdrawn_consents -> List("subject1", "subject2", "subject3", "maarten"))
    val resultWithout = pdpWithout.evaluate("maarten", "view", "doc123",
      wo.subject.roles -> List("medical_personnel", "physician"),
      wo.subject.triggered_breaking_glass -> false,
      wo.subject.department -> "department-not-allowed",
      wo.resource.type_ -> "patientstatus",
      wo.resource.owner_withdrawn_consents -> List("subject1", "subject2", "subject3", "maarten"))
    assert(resultWith.decision === resultWithout.decision)
    assert(resultWith.obligationActions === resultWithout.obligationActions)
    // ignore the employed attributes for now
  }

  @Test def testPhysicianDepartment2() {
    val resultWith = pdpWith.evaluate("maarten", "view", "doc123",
      w.subject.roles -> List(w.medical_personel, w.physician),
      w.subject.triggered_breaking_glass -> true,
      w.subject.department -> "cardiology",
      w.resource.htype -> w.patientStatus,
      w.resource.owner_withdrawn_consents -> List("subject1", "subject2", "subject3", "maarten"))
    val resultWithout = pdpWithout.evaluate("maarten", "view", "doc123",
      wo.subject.roles -> List("medical_personnel", "physician"),
      wo.subject.triggered_breaking_glass -> true,
      wo.subject.department -> "cardiology",
      wo.resource.type_ -> "patientstatus",
      wo.resource.owner_withdrawn_consents -> List("subject1", "subject2", "subject3", "maarten"))
    assert(resultWith.decision === resultWithout.decision)
    assert(resultWith.obligationActions === resultWithout.obligationActions)
    // ignore the employed attributes for now
  }

  @Test def testPhysicianDepartment3() {
    val resultWith = pdpWith.evaluate("maarten", "view", "doc123",
      w.subject.roles -> List(w.medical_personel, w.physician),
      w.subject.triggered_breaking_glass -> true,
      w.subject.department -> "elder_care",
      w.resource.htype -> w.patientStatus,
      w.resource.owner_withdrawn_consents -> List("subject1", "subject2", "subject3", "maarten"))
    val resultWithout = pdpWithout.evaluate("maarten", "view", "doc123",
      wo.subject.roles -> List("medical_personnel", "physician"),
      wo.subject.triggered_breaking_glass -> true,
      wo.subject.department -> "elder_care",
      wo.resource.type_ -> "patientstatus",
      wo.resource.owner_withdrawn_consents -> List("subject1", "subject2", "subject3", "maarten"))
    assert(resultWith.decision === resultWithout.decision)
    assert(resultWith.obligationActions === resultWithout.obligationActions)
    // ignore the employed attributes for now
  }

  @Test def testPhysicianDepartment4() {
    val resultWith = pdpWith.evaluate("maarten", "view", "doc123",
      w.subject.roles -> List(w.medical_personel, w.physician),
      w.subject.triggered_breaking_glass -> true,
      w.subject.department -> "emergency",
      w.resource.htype -> w.patientStatus,
      w.resource.owner_withdrawn_consents -> List("subject1", "subject2", "subject3", "maarten"))
    val resultWithout = pdpWithout.evaluate("maarten", "view", "doc123",
      wo.subject.roles -> List("medical_personnel", "physician"),
      wo.subject.triggered_breaking_glass -> true,
      wo.subject.department -> "emergency",
      wo.resource.type_ -> "patientstatus",
      wo.resource.owner_withdrawn_consents -> List("subject1", "subject2", "subject3", "maarten"))
    assert(resultWith.decision === resultWithout.decision)
    assert(resultWith.obligationActions === resultWithout.obligationActions)
    // ignore the employed attributes for now
  }

  @Test def testPermitPhysicianEmergency1() {
    val resultWith = pdpWith.evaluate("maarten", "view", "doc123",
      w.subject.roles -> List(w.medical_personel, w.physician),
      w.subject.triggered_breaking_glass -> true,
      w.subject.department -> "cardiology",
      w.resource.htype -> w.patientStatus,
      w.resource.owner_withdrawn_consents -> List("subject1", "subject2", "subject3"))
    val resultWithout = pdpWithout.evaluate("maarten", "view", "doc123",
      wo.subject.roles -> List("medical_personnel", "physician"),
      wo.subject.triggered_breaking_glass -> true,
      wo.subject.department -> "cardiology",
      wo.resource.type_ -> "patientstatus",
      wo.resource.owner_withdrawn_consents -> List("subject1", "subject2", "subject3"))
  }

  @Test def testPermitPhysicianEmergency2() {
    val resultWith = pdpWith.evaluate("maarten", "view", "doc123",
      w.subject.roles -> List(w.medical_personel, w.physician),
      w.subject.triggered_breaking_glass -> false,
      w.subject.department -> "cardiology",
      w.resource.htype -> w.patientStatus,
      w.resource.owner_withdrawn_consents -> List("subject1", "subject2", "subject3"),
      w.resource.operator_triggered_emergency -> true)
    val resultWithout = pdpWithout.evaluate("maarten", "view", "doc123",
      wo.subject.roles -> List("medical_personnel", "physician"),
      wo.subject.triggered_breaking_glass -> false,
      wo.subject.department -> "cardiology",
      wo.resource.type_ -> "patientstatus",
      wo.resource.owner_withdrawn_consents -> List("subject1", "subject2", "subject3"),
      wo.resource.operator_triggered_emergency -> true)
    assert(resultWith.decision === resultWithout.decision)
    assert(resultWith.obligationActions === resultWithout.obligationActions)
    // ignore the employed attributes for now
  }

  @Test def testPermitPhysicianEmergency3() {
    val resultWith = pdpWith.evaluate("maarten", "view", "doc123",
      w.subject.roles -> List(w.medical_personel, w.physician),
      w.subject.triggered_breaking_glass -> false,
      w.subject.department -> "cardiology",
      w.resource.htype -> w.patientStatus,
      w.resource.owner_withdrawn_consents -> List("subject1", "subject2", "subject3"),
      w.resource.operator_triggered_emergency -> false,
      w.resource.indicates_emergency -> true)
    val resultWithout = pdpWithout.evaluate("maarten", "view", "doc123",
      wo.subject.roles -> List("medical_personnel", "physician"),
      wo.subject.triggered_breaking_glass -> false,
      wo.subject.department -> "cardiology",
      wo.resource.type_ -> "patientstatus",
      wo.resource.owner_withdrawn_consents -> List("subject1", "subject2", "subject3"),
      wo.resource.operator_triggered_emergency -> false,
      wo.resource.indicates_emergency -> true)
    assert(resultWith.decision === resultWithout.decision)
    assert(resultWith.obligationActions === resultWithout.obligationActions)
    // ignore the employed attributes for now
  }

  @Test def testOverrideWithdrawnConsents {
    val resultWith = pdpWith.evaluate("maarten", "view", "doc123",
      w.subject.roles -> List(w.medical_personel, w.physician),
      w.subject.triggered_breaking_glass -> true,
      w.subject.department -> "cardiology",
      w.resource.htype -> w.patientStatus,
      w.resource.owner_withdrawn_consents -> List("subject1", "subject2", "subject3", "maarten"))
    val resultWithout = pdpWithout.evaluate("maarten", "view", "doc123",
      wo.subject.roles -> List("medical_personnel", "physician"),
      wo.subject.triggered_breaking_glass -> true,
      wo.subject.department -> "cardiology",
      wo.resource.type_ -> "patientstatus",
      wo.resource.owner_withdrawn_consents -> List("subject1", "subject2", "subject3", "maarten"))
    assert(resultWith.decision === resultWithout.decision)
    assert(resultWith.obligationActions === resultWithout.obligationActions)
    // ignore the employed attributes for now
  }

  @Test def testPermitNurseOfElderCareDepartment {
    val resultWith = pdpWith.evaluate("maarten", "view", "doc123",
      w.subject.roles -> List(w.medical_personel, w.nurse),
      w.subject.triggered_breaking_glass -> false,
      w.subject.department -> "elder_care",
      w.subject.allowed_to_access_pms -> true,
      w.subject.shift_start -> new LocalDateTime(2014, 6, 24, 9, 0, 0),
      w.subject.shift_stop -> new LocalDateTime(2014, 6, 24, 17, 0, 0),
      w.subject.location -> "hospital",
      w.subject.admitted_patients_in_nurse_unit -> List("patientX", "patientY"),
      w.subject.responsible_patients -> List("patientX", "patientZ"),
      w.resource.owner_id -> "patientX",
      w.resource.owner_withdrawn_consents -> List("subject1"),
      w.resource.htype -> w.patientStatus,
      w.resource.created -> new LocalDateTime(2014, 6, 22, 14, 2, 1), // three days ago
      w.environment.currentDateTime -> new LocalDateTime(2014, 6, 24, 14, 2, 1))
    val resultWithout = pdpWithout.evaluate("maarten", "view", "doc123",
      wo.subject.roles -> List("medical_personnel", "nurse"),
      wo.subject.triggered_breaking_glass -> false,
      wo.subject.department -> "elder_care",
      wo.subject.allowed_to_access_pms -> true,
      wo.subject.shift_start -> new LocalDateTime(2014, 6, 24, 9, 0, 0),
      wo.subject.shift_stop -> new LocalDateTime(2014, 6, 24, 17, 0, 0),
      wo.subject.location -> "hospital",
      wo.subject.admitted_patients_in_nurse_unit -> List("patientX", "patientY"),
      wo.subject.responsible_patients -> List("patientX", "patientZ"),
      wo.resource.owner_id -> "patientX",
      wo.resource.owner_withdrawn_consents -> List("subject1"),
      wo.resource.type_ -> "patientstatus",
      wo.resource.created -> new LocalDateTime(2014, 6, 22, 14, 2, 1), // three days ago
      wo.environment.currentDateTime -> new LocalDateTime(2014, 6, 24, 14, 2, 1))
    assert(resultWith.decision === resultWithout.decision)
    assert(resultWith.obligationActions === resultWithout.obligationActions)
    // ignore the employed attributes for now
  }

  @Test def testDenyNurseOfElderCareDepartmentNotAllowed {
    val resultWith = pdpWith.evaluate("maarten", "view", "doc123",
      w.subject.roles -> List(w.medical_personel, w.nurse),
      w.subject.triggered_breaking_glass -> false,
      w.subject.department -> "elder_care",
      w.subject.allowed_to_access_pms -> false, // X
      w.subject.shift_start -> new LocalDateTime(2014, 6, 24, 9, 0, 0),
      w.subject.shift_stop -> new LocalDateTime(2014, 6, 24, 17, 0, 0),
      w.subject.location -> "hospital",
      w.subject.admitted_patients_in_nurse_unit -> List("patientX", "patientY"),
      w.subject.responsible_patients -> List("patientX", "patientZ"),
      w.resource.owner_id -> "patientX",
      w.resource.owner_withdrawn_consents -> List("subject1"),
      w.resource.htype -> w.patientStatus,
      w.resource.created -> new LocalDateTime(2014, 6, 22, 14, 2, 1), // three days ago
      w.environment.currentDateTime -> new LocalDateTime(2014, 6, 24, 14, 2, 1))
    val resultWithout = pdpWithout.evaluate("maarten", "view", "doc123",
      wo.subject.roles -> List("medical_personnel", "nurse"),
      wo.subject.triggered_breaking_glass -> false,
      wo.subject.department -> "elder_care",
      wo.subject.allowed_to_access_pms -> false, // X
      wo.subject.shift_start -> new LocalDateTime(2014, 6, 24, 9, 0, 0),
      wo.subject.shift_stop -> new LocalDateTime(2014, 6, 24, 17, 0, 0),
      wo.subject.location -> "hospital",
      wo.subject.admitted_patients_in_nurse_unit -> List("patientX", "patientY"),
      wo.subject.responsible_patients -> List("patientX", "patientZ"),
      wo.resource.owner_id -> "patientX",
      wo.resource.owner_withdrawn_consents -> List("subject1"),
      wo.resource.type_ -> "patientstatus",
      wo.resource.created -> new LocalDateTime(2014, 6, 22, 14, 2, 1), // three days ago
      wo.environment.currentDateTime -> new LocalDateTime(2014, 6, 24, 14, 2, 1))
    assert(resultWith.decision === resultWithout.decision)
    assert(resultWith.obligationActions === resultWithout.obligationActions)
    // ignore the employed attributes for now
  }

  @Test def testDenyNurseOfElderCareDepartmentNotAtHospital {
    val resultWith = pdpWith.evaluate("maarten", "view", "doc123",
      w.subject.roles -> List(w.medical_personel, w.nurse),
      w.subject.triggered_breaking_glass -> false,
      w.subject.department -> "elder_care",
      w.subject.allowed_to_access_pms -> true,
      w.subject.shift_start -> new LocalDateTime(2014, 6, 24, 9, 0, 0),
      w.subject.shift_stop -> new LocalDateTime(2014, 6, 24, 17, 0, 0),
      w.subject.location -> "somewhere-not-the-hospital", // X
      w.subject.admitted_patients_in_nurse_unit -> List("patientX", "patientY"),
      w.subject.responsible_patients -> List("patientX", "patientZ"),
      w.resource.owner_id -> "patientX",
      w.resource.owner_withdrawn_consents -> List("subject1"),
      w.resource.htype -> w.patientStatus,
      w.resource.created -> new LocalDateTime(2014, 6, 22, 14, 2, 1), // three days ago
      w.environment.currentDateTime -> new LocalDateTime(2014, 6, 24, 14, 2, 1))
    val resultWithout = pdpWithout.evaluate("maarten", "view", "doc123",
      wo.subject.roles -> List("medical_personnel", "nurse"),
      wo.subject.triggered_breaking_glass -> false,
      wo.subject.department -> "elder_care",
      wo.subject.allowed_to_access_pms -> true,
      wo.subject.shift_start -> new LocalDateTime(2014, 6, 24, 9, 0, 0),
      wo.subject.shift_stop -> new LocalDateTime(2014, 6, 24, 17, 0, 0),
      wo.subject.location -> "somewhere-not-the-hospital", // X
      wo.subject.admitted_patients_in_nurse_unit -> List("patientX", "patientY"),
      wo.subject.responsible_patients -> List("patientX", "patientZ"),
      wo.resource.owner_id -> "patientX",
      wo.resource.owner_withdrawn_consents -> List("subject1"),
      wo.resource.type_ -> "patientstatus",
      wo.resource.created -> new LocalDateTime(2014, 6, 22, 14, 2, 1), // three days ago
      wo.environment.currentDateTime -> new LocalDateTime(2014, 6, 24, 14, 2, 1))
    assert(resultWith.decision === resultWithout.decision)
    assert(resultWith.obligationActions === resultWithout.obligationActions)
    // ignore the employed attributes for now
  }

  @Test def testDenyNurseOfElderCareDepartmentNotInNurseUnit {
    val resultWith = pdpWith.evaluate("maarten", "view", "doc123",
      w.subject.roles -> List(w.medical_personel, w.nurse),
      w.subject.triggered_breaking_glass -> false,
      w.subject.department -> "elder_care",
      w.subject.allowed_to_access_pms -> true,
      w.subject.shift_start -> new LocalDateTime(2014, 6, 24, 9, 0, 0),
      w.subject.shift_stop -> new LocalDateTime(2014, 6, 24, 17, 0, 0),
      w.subject.location -> "hospital",
      w.subject.admitted_patients_in_nurse_unit -> List("patientZ", "patientY"), // X 
      w.subject.responsible_patients -> List("patientX", "patientZ"),
      w.resource.owner_id -> "patientX",
      w.resource.owner_withdrawn_consents -> List("subject1"),
      w.resource.htype -> w.patientStatus,
      w.resource.created -> new LocalDateTime(2014, 6, 22, 14, 2, 1), // three days ago
      w.environment.currentDateTime -> new LocalDateTime(2014, 6, 24, 14, 2, 1))
    val resultWithout = pdpWithout.evaluate("maarten", "view", "doc123",
      wo.subject.roles -> List("medical_personnel", "nurse"),
      wo.subject.triggered_breaking_glass -> false,
      wo.subject.department -> "elder_care",
      wo.subject.allowed_to_access_pms -> true,
      wo.subject.shift_start -> new LocalDateTime(2014, 6, 24, 9, 0, 0),
      wo.subject.shift_stop -> new LocalDateTime(2014, 6, 24, 17, 0, 0),
      wo.subject.location -> "hospital",
      wo.subject.admitted_patients_in_nurse_unit -> List("patientZ", "patientY"), // X 
      wo.subject.responsible_patients -> List("patientX", "patientZ"),
      wo.resource.owner_id -> "patientX",
      wo.resource.owner_withdrawn_consents -> List("subject1"),
      wo.resource.type_ -> "patientstatus",
      wo.resource.created -> new LocalDateTime(2014, 6, 22, 14, 2, 1), // three days ago
      wo.environment.currentDateTime -> new LocalDateTime(2014, 6, 24, 14, 2, 1))
    assert(resultWith.decision === resultWithout.decision)
    assert(resultWith.obligationActions === resultWithout.obligationActions)
    // ignore the employed attributes for now
  }

  @Test def testDenyNurseOfElderCareDepartmentNotResponsible {
    val resultWith = pdpWith.evaluate("maarten", "view", "doc123",
      w.subject.roles -> List(w.medical_personel, w.nurse),
      w.subject.triggered_breaking_glass -> false,
      w.subject.department -> "elder_care",
      w.subject.allowed_to_access_pms -> true,
      w.subject.shift_start -> new LocalDateTime(2014, 6, 24, 9, 0, 0),
      w.subject.shift_stop -> new LocalDateTime(2014, 6, 24, 17, 0, 0),
      w.subject.location -> "hospital",
      w.subject.admitted_patients_in_nurse_unit -> List("patientX", "patientY"),
      w.subject.responsible_patients -> List("patientY", "patientZ"),
      w.resource.owner_id -> "patientX",
      w.resource.owner_withdrawn_consents -> List("subject1"),
      w.resource.htype -> w.patientStatus,
      w.resource.created -> new LocalDateTime(2014, 6, 22, 14, 2, 1), // three days ago
      w.environment.currentDateTime -> new LocalDateTime(2014, 6, 24, 14, 2, 1))
    val resultWithout = pdpWithout.evaluate("maarten", "view", "doc123",
      wo.subject.roles -> List("medical_personnel", "nurse"),
      wo.subject.triggered_breaking_glass -> false,
      wo.subject.department -> "elder_care",
      wo.subject.allowed_to_access_pms -> true,
      wo.subject.shift_start -> new LocalDateTime(2014, 6, 24, 9, 0, 0),
      wo.subject.shift_stop -> new LocalDateTime(2014, 6, 24, 17, 0, 0),
      wo.subject.location -> "hospital",
      wo.subject.admitted_patients_in_nurse_unit -> List("patientX", "patientY"),
      wo.subject.responsible_patients -> List("patientY", "patientZ"),
      wo.resource.owner_id -> "patientX",
      wo.resource.owner_withdrawn_consents -> List("subject1"),
      wo.resource.type_ -> "patientstatus",
      wo.resource.created -> new LocalDateTime(2014, 6, 22, 14, 2, 1), // three days ago
      wo.environment.currentDateTime -> new LocalDateTime(2014, 6, 24, 14, 2, 1))
    assert(resultWith.decision === resultWithout.decision)
    assert(resultWith.obligationActions === resultWithout.obligationActions)
    // ignore the employed attributes for now
  }

  @Test def testDenyNurseOfElderCareDepartmentNotOwner {
    val resultWith = pdpWith.evaluate("maarten", "view", "doc123",
      w.subject.roles -> List(w.medical_personel, w.nurse),
      w.subject.triggered_breaking_glass -> false,
      w.subject.department -> "elder_care",
      w.subject.allowed_to_access_pms -> true,
      w.subject.shift_start -> new LocalDateTime(2014, 6, 24, 9, 0, 0),
      w.subject.shift_stop -> new LocalDateTime(2014, 6, 24, 17, 0, 0),
      w.subject.location -> "hospital",
      w.subject.admitted_patients_in_nurse_unit -> List("patientX", "patientY"),
      w.subject.responsible_patients -> List("patientX", "patientZ"),
      w.resource.owner_id -> "patientA",
      w.resource.owner_withdrawn_consents -> List("subject1"),
      w.resource.htype -> w.patientStatus,
      w.resource.created -> new LocalDateTime(2014, 6, 22, 14, 2, 1), // three days ago
      w.environment.currentDateTime -> new LocalDateTime(2014, 6, 24, 14, 2, 1))
    val resultWithout = pdpWithout.evaluate("maarten", "view", "doc123",
      wo.subject.roles -> List("medical_personnel", "nurse"),
      wo.subject.triggered_breaking_glass -> false,
      wo.subject.department -> "elder_care",
      wo.subject.allowed_to_access_pms -> true,
      wo.subject.shift_start -> new LocalDateTime(2014, 6, 24, 9, 0, 0),
      wo.subject.shift_stop -> new LocalDateTime(2014, 6, 24, 17, 0, 0),
      wo.subject.location -> "hospital",
      wo.subject.admitted_patients_in_nurse_unit -> List("patientX", "patientY"),
      wo.subject.responsible_patients -> List("patientX", "patientZ"),
      wo.resource.owner_id -> "patientA",
      wo.resource.owner_withdrawn_consents -> List("subject1"),
      wo.resource.type_ -> "patientstatus",
      wo.resource.created -> new LocalDateTime(2014, 6, 22, 14, 2, 1), // three days ago
      wo.environment.currentDateTime -> new LocalDateTime(2014, 6, 24, 14, 2, 1))
    assert(resultWith.decision === resultWithout.decision)
    assert(resultWith.obligationActions === resultWithout.obligationActions)
    // ignore the employed attributes for now
  }

  @Test def testDenyNurseOfElderCareDepartmentTooLongAgo {
    val resultWith = pdpWith.evaluate("maarten", "view", "doc123",
      w.subject.roles -> List(w.medical_personel, w.nurse),
      w.subject.triggered_breaking_glass -> false,
      w.subject.department -> "elder_care",
      w.subject.allowed_to_access_pms -> true,
      w.subject.shift_start -> new LocalDateTime(2014, 6, 24, 9, 0, 0),
      w.subject.shift_stop -> new LocalDateTime(2014, 6, 24, 17, 0, 0),
      w.subject.location -> "hospital",
      w.subject.admitted_patients_in_nurse_unit -> List("patientX", "patientY"),
      w.subject.responsible_patients -> List("patientX", "patientZ"),
      w.resource.owner_id -> "patientX",
      w.resource.owner_withdrawn_consents -> List("subject1"),
      w.resource.htype -> w.patientStatus,
      w.resource.created -> new LocalDateTime(2014, 6, 1, 14, 2, 1), // X more than five days ago
      w.environment.currentDateTime -> new LocalDateTime(2014, 6, 24, 14, 2, 1))
    val resultWithout = pdpWithout.evaluate("maarten", "view", "doc123",
      wo.subject.roles -> List("medical_personnel", "nurse"),
      wo.subject.triggered_breaking_glass -> false,
      wo.subject.department -> "elder_care",
      wo.subject.allowed_to_access_pms -> true,
      wo.subject.shift_start -> new LocalDateTime(2014, 6, 24, 9, 0, 0),
      wo.subject.shift_stop -> new LocalDateTime(2014, 6, 24, 17, 0, 0),
      wo.subject.location -> "hospital",
      wo.subject.admitted_patients_in_nurse_unit -> List("patientX", "patientY"),
      wo.subject.responsible_patients -> List("patientX", "patientZ"),
      wo.resource.owner_id -> "patientX",
      wo.resource.owner_withdrawn_consents -> List("subject1"),
      wo.resource.type_ -> "patientstatus",
      wo.resource.created -> new LocalDateTime(2014, 6, 1, 14, 2, 1), // X more than five days ago
      wo.environment.currentDateTime -> new LocalDateTime(2014, 6, 24, 14, 2, 1))
    assert(resultWith.decision === resultWithout.decision)
    assert(resultWith.obligationActions === resultWithout.obligationActions)
    // ignore the employed attributes for now
  }
}