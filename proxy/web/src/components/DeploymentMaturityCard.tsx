import { Card } from "@/components/Card";
import { Title } from "@/components/Title";
import { Description } from "@/components/Description";
import { Separator } from "@/components/Separator";

type DeploymentMaturityStage = "exploration" | "functional" | "operational" | "production";

type DeploymentMaturityCardProps = {
  stage: DeploymentMaturityStage | null;
};

export const DeploymentMaturityCard = ({ stage }: DeploymentMaturityCardProps) => {
  if (!stage) {
    return null;
  }

  const titleByStage: Record<DeploymentMaturityStage, string> = {
    exploration: "Exploration deployment",
    functional: "Functional deployment",
    operational: "Operational deployment",
    production: "Production deployment",
  };

  const descriptionByStage: Record<DeploymentMaturityStage, string> = {
    exploration:
      "This deployment is suitable for initial testing. Review core setup, access policies, and peer coverage before relying on it for daily work.",
    functional:
      "This deployment covers basic connectivity. Review routing, DNS, and access policies to ensure they match how your team actually works.",
    operational:
      "This deployment supports day-to-day use. Periodically review audit events, policy changes, and onboarding flows to keep it predictable.",
    production:
      "This deployment is ready for sustained production use. Keep an eye on change management, observability, and backup procedures.",
  };

  const titleText = titleByStage[stage];
  const descriptionText = descriptionByStage[stage];

  return (
    <Card className="max-w-105 mx-auto mb-6">
      <Title>{titleText}</Title>
      <Description>{descriptionText}</Description>
      <Separator />
    </Card>
  );
};

