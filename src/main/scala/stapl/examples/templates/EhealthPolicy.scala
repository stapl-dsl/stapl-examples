package stapl.examples.templates

import stapl.core._
import stapl.templates.casestudies.Treating
import stapl.templates.casestudies.Shifts
import stapl.templates.general.Location
import stapl.templates.casestudies.HospitalPolicy
import stapl.templates.rbac._
import stapl.templates.htype._

/**
 * This is stapl.core.examples.EhealthPolicy cleaned up with the templates
 */
object EhealthPolicy extends HospitalPolicy {

  // The policy set for "view patient status".
  val policy = Policy("ehealth") := when (action.id === "view" & resource.hasType(patientStatus)) apply DenyOverrides to (    
    // The consent policy.
    Policy("policy:1") := when (subject.hasRole(medical_personel)) apply PermitOverrides to (
        Rule("consent") := deny iff (subject.id in resource.owner_withdrawn_consents),
        Rule("breaking-glass") := permit iff (subject.triggered_breaking_glass) performing (log(subject.id + " performed breaking-the-glass procedure"))
    ) performing (log("permit because of breaking-the-glass procedure") on Permit),
    
    // Only physicians, nurses and patients can access the monitoring system.
    // Rule("policy:2") := deny iff !(("nurse" in subject.roles) | ("physician" in subject.roles) | ("patient" in subject.roles)),
    denyIfNotOneOf(nurse, physician, patient),
    
    // For physicians.
    Policy("policyset:2") := when (subject.hasRole(physician)) apply FirstApplicable to (      
      // Of the physicians, only gps, physicians of the cardiology department, physicians of the elder care department and physicians of the emergency department can access the monitoring system.
      Rule("policy:3") := deny iff !((subject.department === cardiology) | (subject.department === elder_care) | (subject.department === emergency) | subject.hasRole(gp)),
      
      // All of the previous physicians can access the monitoring system in case of emergency.
      Rule("policy:4") := when ((subject.department === cardiology) | (subject.department === elder_care) | (subject.department === emergency))
        permit iff (subject.triggered_breaking_glass | resource.operator_triggered_emergency | resource.indicates_emergency),
      
      // For GPs: only permit if in consultation or treated in the last six months or primary physician or responsible in the system.
      OnlyPermitIff("policyset:3")(
          target = subject.hasRole(gp),
          (resource.owner_id === subject.current_patient_in_consultation)
          | (resource.owner_id in subject.treated_in_last_six_months)
          | (resource.owner_id in subject.primary_patients)
          | (subject.id in resource.owner_responsible_physicians)
      ),
      
      // For cardiologists.
      Policy("policyset:4") := when (subject.department === cardiology) apply PermitOverrides to (        
        // Permit for head physician.
        Rule("policy:7") := permit iff (subject.is_head_physician),
        
        // Permit if treated the patient or treated in team.
        Rule("policy:8") := permit iff (resource.owner_id in subject.treated) | (resource.owner_id in subject.treated_by_team),
        
        Rule("policy:9") := deny
      ),
      
      // For physicians of elder care department: only permit if admitted in care unit or treated in the last six months.
      OnlyPermitIff("policyset:5")(
          target = subject.department === elder_care,
          (resource.owner_id in subject.admitted_patients_in_care_unit)
          | (resource.owner_id in subject.treated_in_last_six_months)
      ),
      
      // For physicians of emergency department: only permit if patient status is bad (or the above).
      OnlyPermitIff("policyset:6")(
          target = subject.department === emergency,   
          resource.patient_status === "bad"
      )
    ),
    
    // For nurses.
    Policy("policyset:7") := when (subject.hasRole(nurse)) apply FirstApplicable to (      
      // Of the nurses, only nurses of the cardiology department or the elder care department can access the PMS.
      Rule("policy:14") := deny iff !((subject.department === cardiology) | (subject.department === elder_care)),
      
      // Nurses can only access the PMS during their shifts.
      Rule("policy:15") := deny iff !((environment.currentDateTime gteq subject.shift_start) & (environment.currentDateTime lteq subject.shift_stop)),
      
      // Nurses can only access the PMS from the hospital.
      Rule("policy:16") := deny iff !(subject.location === "hospital"),
      
      // Nurses can only view the patient's status of the last five days.
      Rule("policy:17") := deny iff !(environment.currentDateTime lteq (resource.created + 5.days)),
      
      // For nurses of cardiology department: they can only view the patient status of a patient 
      // in their nurse unit for whom they are assigned responsible, up to three days after they were discharged.
      OnlyPermitIff("policyset:8")(
          target = subject.department === cardiology,
          (resource.owner_id in subject.admitted_patients_in_nurse_unit) 
          	& (!resource.owner_discharged | (environment.currentDateTime lteq (resource.owner_discharged_dateTime + 3.days)))
      ),
        
      // For nurses of the elder care department.
      Policy("policyset:9") := when (subject.department === elder_care) apply DenyOverrides to (
        // Of the nurses of the elder care department, only nurses who have been allowed to use the PMS can access the PMS.
        Rule("policy:20") := deny iff !subject.allowed_to_access_pms,
        
        // Nurses of the elder care department can only view the patient status of a patient 
        // who is currently admitted to their nurse unit and for whome they are assigned responsible.
        OnlyPermitIff("policySet:10")(
            target = AlwaysTrue,
            (resource.owner_id in subject.admitted_patients_in_nurse_unit) 
            	& (resource.owner_id in subject.responsible_patients)
        )
      )
    ),
    // For patients
    Policy("policyset:11") := when (subject.hasRole(patient)) apply FirstApplicable to (      
	      // A patient can only access the PMS if (still) allowed by the hospital (e.g., has 
    	  // subscribed to the PMS, but is not paying any more).
	      Rule("policy:23") := deny iff !subject.allowed_to_access_pms,
	      
	      // A patient can only view his own status.
	      Rule("policy:24") := deny iff !(resource.owner_id === subject.id),
	      
	      Rule("policy:25") := permit
    )
  )
}