import FancyToggleSwitch from "@/components/FancyToggleSwitch";
import { SectionGroup } from "@/modules/settings/SettingsSection.tsx";
import { useAppearance } from "@/modules/appearance/AppearanceContext.tsx";

export function SettingsAppearance() {
    const {
        showPeersNav,
        showResourcesNav,
        showExitNodeNav,
        showProfileSelector,
        showSettingsButton,
        setField,
    } = useAppearance();

    return (
        <SectionGroup title={"Interface"}>
            <FancyToggleSwitch
                value={showPeersNav}
                onChange={(v) => setField("showPeersNav", v)}
                label={"Peers"}
                helpText={"Show the Peers item in the side navigation."}
            />
            <FancyToggleSwitch
                value={showResourcesNav}
                onChange={(v) => setField("showResourcesNav", v)}
                label={"Resources"}
                helpText={"Show the Resources item in the side navigation."}
            />
            <FancyToggleSwitch
                value={showExitNodeNav}
                onChange={(v) => setField("showExitNodeNav", v)}
                label={"Exit Node"}
                helpText={"Show the active exit node in the side navigation."}
            />
            <FancyToggleSwitch
                value={showProfileSelector}
                onChange={(v) => setField("showProfileSelector", v)}
                label={"Profile Selector"}
                helpText={"Show the profile selector in the header."}
            />
            <FancyToggleSwitch
                value={showSettingsButton}
                onChange={(v) => setField("showSettingsButton", v)}
                label={"Settings Button"}
                helpText={"Show the settings button in the header."}
            />
        </SectionGroup>
    );
}
