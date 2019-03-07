package review.aws;

import java.util.Date;
import java.util.List;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.cloudtrail.AWSCloudTrail;
import com.amazonaws.services.cloudtrail.AWSCloudTrailClientBuilder;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2ClientBuilder;
import com.amazonaws.services.ec2.model.DescribeSecurityGroupsRequest;
import com.amazonaws.services.ec2.model.DescribeSecurityGroupsResult;
import com.amazonaws.services.ec2.model.IpPermission;
import com.amazonaws.services.ec2.model.IpRange;
import com.amazonaws.services.ec2.model.SecurityGroup;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagement;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementClientBuilder;
import com.amazonaws.services.identitymanagement.model.AccessKeyMetadata;
import com.amazonaws.services.identitymanagement.model.ListAccessKeysRequest;
import com.amazonaws.services.identitymanagement.model.ListAccessKeysResult;
import com.amazonaws.services.rds.AmazonRDS;
import com.amazonaws.services.rds.AmazonRDSClientBuilder;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.bespin.portal.governance.model.ComplianceOutputModel;

public class UsedAwsSdk {

	public static void main(String[] args) {
		
		BasicAWSCredentials credential = new BasicAWSCredentials(acskey,scrtkey);
		AWSStaticCredentialsProvider credentialsProvider = new AWSStaticCredentialsProvider(credential);
		System.out.println("aws credential provier 생성 완료");
		
		String region = "us-east-1";
		System.out.println("Client Region : "+region);
		
		AmazonIdentityManagement clientIam = AmazonIdentityManagementClientBuilder
				.standard()
				.withCredentials(credentialsProvider)
				.withRegion(region)
				.build();
		System.out.println("aws iam client 생성 완료");
		AmazonEC2 clientEc2 = AmazonEC2ClientBuilder
				.standard()
				.withCredentials(credentialsProvider)
				.withRegion(region)
				.build();
		System.out.println("aws ec2 client 생성 완료");
		AmazonS3 clientS3 = AmazonS3ClientBuilder
				.standard()
				.withCredentials(credentialsProvider)
				.withRegion(region)
				.build();
		System.out.println("aws s3 client 생성 완료");
		AmazonRDS clientRds = AmazonRDSClientBuilder
				.standard()
				.withCredentials(credentialsProvider)
				.withRegion(region)
				.build();
		System.out.println("aws rds client 생성완료");
		AWSCloudTrail clientCloudTrail = AWSCloudTrailClientBuilder
				.standard()
				.withCredentials(credentialsProvider)
				.withRegion(region)
				.build();
		System.out.println("aws cloudTrail client 생성완료");
		System.out.println("");
		System.out.println("");
		System.out.println("");
		
		try {
			// title : IAM IAM User has access key(s) that needs rotation
			IAMAccessKeyRotation(clientIam);	
		}catch(Exception e) {
			System.out.println("Error !!! "+ e.getMessage());
			System.out.println("");
			System.out.println("");
			System.out.println("");
		}
		
		try {
			// title : EC2 Security Group has large ingress port range
			EC2SecurityGrouphaslargeingressportrange(clientEc2);
		}catch(Exception e) {
			System.out.println("Error !!! "+ e.getMessage());
			System.out.println("");
			System.out.println("");
			System.out.println("");
		}
		
		try {
			// title : EC2 Security Group Egress Range
			EC2SecurityGroupEgressRange(clientEc2);
		}catch(Exception e) {
			System.out.println("Error !!! "+ e.getMessage());
			System.out.println("");
			System.out.println("");
			System.out.println("");
		}

	}

	static void IAMAccessKeyRotation(AmazonIdentityManagement clientIam) {
		System.out.println("******** title : IAM IAM User has access key(s) that needs rotation");
		System.out.println("******** description : access key 생성한지{n} day가  지났으면  fail");
		System.out.println("******** 사용 client : IAM, 사용 method : listAccessKeys");
		// 해당 로직은 하나의 user에 대해서 key 조회함, user list 불러온 다음에 조회하도록 수정해야함.
		
		int day = 60;
		System.out.println("기준 일 : "+ day +"day");
		ListAccessKeysRequest request = new ListAccessKeysRequest();
		ListAccessKeysResult response = clientIam.listAccessKeys(request);
		List<AccessKeyMetadata> keyList = response.getAccessKeyMetadata();
		if(keyList == null || keyList.size()==0) {
			System.out.println("해당 condition에 대하여 fail입니다. access key가 없습니다.");
		}

		Date curDate = new Date(System.currentTimeMillis());
		for(AccessKeyMetadata key : keyList) {
			long diff = (curDate.getTime() - key.getCreateDate().getTime()) / (24*60*60*1000);
			System.out.println("Date difference : " + diff);
			if(diff>day) {
				System.out.println("해당 condition에 대하여 fail입니다. Diff Day : "+diff);	
			}else {
				System.out.println("해당 condition에 대하여 success입니다.");
			}
		}
		System.out.println("");
		System.out.println("");
		System.out.println("");
	}
	
	static ComplianceOutputModel EC2SecurityGrouphaslargeingressportrange(AmazonEC2 clientEc2, int... value) {
		System.out.println("******** title : Security Group EC2 Security Group has large ingress port range");
		System.out.println("******** description : toPort - FromPort의 차이가 {value} 이하인것");
		
		int range = value.length > 0 ? value[0] : 0;
		System.out.println("********  value : "+range);
		
		ComplianceOutputModel result = new ComplianceOutputModel();
		
		DescribeSecurityGroupsRequest request = new DescribeSecurityGroupsRequest();
		DescribeSecurityGroupsResult response = clientEc2.describeSecurityGroups(request);
		List<SecurityGroup> sectGrpList = response.getSecurityGroups();
		
		boolean isFail = false;
		String desc = "";
		if(sectGrpList != null && sectGrpList.size()>0) {
			
			for(int i=0; i<sectGrpList.size();i++) {
				System.out.println("security group check >>>" + sectGrpList.get(i).getGroupName());
				List<IpPermission> ipPermission =sectGrpList.get(i).getIpPermissions(); 
				for(int j=0; j<ipPermission.size();j++) {
					IpPermission permission = ipPermission.get(j);
					
					System.out.println("ippermission >>>>>>>"+ipPermission.get(j));
					System.out.println("ippermission toport >>"+ ipPermission.get(j).getToPort());
					System.out.println("ippermission fromPort >>" + ipPermission.get(j).getFromPort());
					
					if(permission.getToPort() == null && permission.getFromPort() == null) {
						isFail = true;
						desc = "[security group name : "+sectGrpList.get(i).getGroupName()+"]에 대하여 fail 입니다."+"- port 제한 없음 ";
						System.out.println();
					}else if(Math.abs(permission.getFromPort()-permission.getToPort()) > range) {
						isFail = true;
						desc = "[security group name : "+sectGrpList.get(i).getGroupName()+"]에 대하여 fail 입니다."+"- port range 초과";
					}
				}
			}
		}else {
			isFail = true;
			desc = "security group이 존재하지 않습니다.";
		}
		
		result.setOutput(!isFail);
		result.setDesc(desc);

		System.out.println("해당 condition에 대하여 "+(isFail ? "fail" : "success")+"입니다.");
		System.out.println(desc);
		
		System.out.println("");
		System.out.println("");
		System.out.println("");
		
		return result;
	}
	static void EC2SecurityGroupEgressRange(AmazonEC2 clientEc2) {
		System.out.println("******** title : Security Group EC2 Security Group Egress Range");
		System.out.println("******** description : security outbound rule에 제한이 있는지 없는지 check");
		
		DescribeSecurityGroupsRequest request = new DescribeSecurityGroupsRequest();
		DescribeSecurityGroupsResult response = clientEc2.describeSecurityGroups(request);
		List<SecurityGroup> sectGrpList = response.getSecurityGroups();
		if(sectGrpList != null && sectGrpList.size()>0) {
			
			for(int i=0; i<sectGrpList.size();i++) {
				System.out.println("security group check >>>" + sectGrpList.get(i));
				List<IpPermission> ipPermission =sectGrpList.get(i).getIpPermissionsEgress(); // 여기만 다르으으음 
				for(int j=0; j<ipPermission.size();j++) {
					IpPermission permission = ipPermission.get(j);
					
					if(permission.getIpProtocol().equals("-1")) {
						System.out.println("[security group name : "+sectGrpList.get(i).getGroupName()+"]에 대하여 fail 입니다."+"- protocal 제한 없음");
					}else{
						if(permission.getIpv4Ranges() != null) {
							for(int z=0; z<permission.getIpv4Ranges().size();z++) {
								IpRange range = permission.getIpv4Ranges().get(z);
								if(range.getCidrIp().contains("0.0.0.0/0")) {
									System.out.println("[security group name : "+sectGrpList.get(i).getGroupName()+"]에 대하여 fail 입니다."+"- ip range unresctict open");
									break;
								}
								
							}
						}
					}
				}
			}
		}
		System.out.println("");
		System.out.println("");
		System.out.println("");	
	}
	
}
