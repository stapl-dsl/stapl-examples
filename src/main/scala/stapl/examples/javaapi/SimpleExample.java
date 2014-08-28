package stapl.examples.javaapi;

import static stapl.javaapi.pdp.attributevalues.AttributeValueFactory.list;
import static stapl.javaapi.pdp.attributevalues.AttributeValueFactory.simple;
import stapl.core.AttributeContainer;
import stapl.core.Policy;
import stapl.core.Result;
import stapl.examples.policies.EdocsPolicy;
import stapl.javaapi.pdp.PDP;

public class SimpleExample {

	public static void main(String[] args) {
		/* Java imitation of the following Scala code:
		
		assert(pdp.evaluate("maarten", "view", "doc123",
	        subject.role -> List("helpdesk"),
	        subject.tenant_name -> List("provider"),
	        subject.tenant_type -> List("provider"),
	        subject.assigned_tenants -> List("tenant1","tenant3"),
	        resource.type_ -> "document",
	        resource.owning_tenant -> "tenant4",
	        resource.confidential -> false) === Result(Deny, List()))
		*/
		
		Policy policy = EdocsPolicy.policy();
		AttributeContainer subject = EdocsPolicy.subject();
		AttributeContainer resource = EdocsPolicy.resource();
		AttributeContainer action = EdocsPolicy.action();
		AttributeContainer env = EdocsPolicy.environment();
		
		PDP pdp = new PDP(policy);
		Result result = pdp.evaluate("maarten", "view", "doc123", 
				list(subject.get("role"), "helpdesk"),
				list(subject.get("tenant_name"), "provider"),
				list(subject.get("tenant_type"), "provider"),
				list(subject.get("assigned_tenants"), "tenant1", "tenant2"),
				simple(resource.get("type_"), "document"),
				simple(resource.get("owning_tenant"), "tenant4"),
				simple(resource.get("confidential"), false));
		System.out.println(result);
	}

}
