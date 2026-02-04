import { useEffect } from "react";
import { BookText, RotateCw } from "lucide-react";
import { Title } from "@/components/Title";
import { Description } from "@/components/Description";
import { PoweredByNetBird } from "@/components/PoweredByNetBird";
import { Card } from "@/components/Card";
import Button from "@/components/Button";
import type { ErrorData } from "@/data";

export function ErrorPage({ code, title, message }: ErrorData) {
  useEffect(() => {
    document.title = `${title} - NetBird Service`;
  }, [title]);

  return (
    <main className="flex flex-col items-center mt-40 px-4 max-w-xl mx-auto">
      <Card className="text-center">
        <div className="text-5xl font-bold text-nb-gray-200 mb-4">{code}</div>
        <Title>{title}</Title>
        <Description className="mt-2">{message}</Description>
        <div className="mt-6 flex gap-3 justify-center">
          <Button
            variant="primary"
            onClick={() => window.location.reload()}
          >
              <RotateCw size={16} />
            Refresh Page
          </Button>
          <Button
            variant="secondary"
            onClick={() => window.open("https://docs.netbird.io", "_blank")}
          >
            <BookText size={16} />
            Documentation
          </Button>
        </div>
      </Card>

      <PoweredByNetBird />
    </main>
  );
}
