package stapl.examples.templates.ehealth.application

import stapl.core.BasicPolicy
import stapl.templates.general.Ownership
import stapl.templates.htype.HTypes
import stapl.templates.general.ResourceCreation
import stapl.core.SimpleAttribute
import stapl.core.Bool
import stapl.core.String
import stapl.templates.htype.HType
import stapl.core.ResourceAttributeContainer
import stapl.core.Expression
import stapl.core.Value
import stapl.core.Number

trait PatientStatus extends BasicPolicy {
  
  resource.patient_status = SimpleAttribute(Number)

  /**
   * The application's resource types.
   */
  val patientStatus = HType("patientstatus")
  
  /**
   * The patient statuses.
   */
  class ResourceWithPatientStatus(resource: ResourceAttributeContainer) {
	  
	  def patientHasStatusOrWorse(status: Value): Expression = status.gteq(resource.patient_status) 
	  
	  def patientHasStatusOrBetter(status: Value): Expression = status.lteq(resource.patient_status)

  }
  implicit def resource2ResourceWithPatientStatus(resource: ResourceAttributeContainer) = new ResourceWithPatientStatus(resource)
  
  //Values: higher is worse.
  val status_good = 5
  val status_ok = 6
  val status_bad = 7
  val status_very_bad = 8
  
}

trait PatientMonitoringSystem extends BasicPolicy
								with Ownership
								with HTypes
								with ResourceCreation
								with PatientStatus {
  //resource.type_ = SimpleAttribute(String)
  resource.operator_triggered_emergency = SimpleAttribute(Bool)
  resource.indicates_emergency = SimpleAttribute(Bool)
  //resource.owner_id = SimpleAttribute("owner:id", String)
  //resource.patient_status = SimpleAttribute(Number)
  //resource.created = SimpleAttribute(DateTime)
  
  /**
   * The application's actions.
   */
  val action_view = "view"
  
}