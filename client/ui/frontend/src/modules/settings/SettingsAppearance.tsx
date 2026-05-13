import FancyToggleSwitch from "@/components/FancyToggleSwitch";
import { CardSelect } from "@/components/CardSelect.tsx";
import { SectionGroup } from "@/modules/settings/SettingsSection.tsx";
import {
    useAppearance,
    type AppearanceView,
} from "@/modules/appearance/AppearanceContext.tsx";
import simpleScreen from "@/assets/screens/simple.png";
import advancedScreen from "@/assets/screens/advanced.png";

const ScreenPreview = ({ src, alt }: { src: string; alt: string }) => (
    <img
        src={src}
        alt={alt}
        draggable={false}
        className={"h-full w-full object-contain select-none"}
    />
);

export function SettingsAppearance() {
    const {
        view,
        setView,
        showPeersNav,
        showResourcesNav,
        showExitNodeNav,
        showProfileSelector,
        showSettingsButton,
        setField,
    } = useAppearance();

    return (
        <>
            <SectionGroup title={"View"}>
                <CardSelect
                    value={view}
                    onChange={(v) => setView(v as AppearanceView)}
                >
                    <CardSelect.Option
                        value={"default"}
                        title={"Simple"}
                        description={"Streamlined view with essential controls."}
                        preview={<ScreenPreview src={simpleScreen} alt={"Simple view"} />}
                    />
                    <CardSelect.Option
                        value={"advanced"}
                        title={"Advanced"}
                        description={"All details and power-user options visible."}
                        preview={<ScreenPreview src={advancedScreen} alt={"Advanced view"} />}
                    />
                </CardSelect>
            </SectionGroup>

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
        </>
    );
}
