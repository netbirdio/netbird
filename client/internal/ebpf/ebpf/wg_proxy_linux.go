package ebpf

import log "github.com/sirupsen/logrus"

const (
	mapKeyProxyPort uint32 = 0
	mapKeyWgPort    uint32 = 1
)

func (tf *GeneralManager) LoadWgProxy(proxyPort, wgPort int) error {
	log.Debugf("load ebpf WG proxy")
	tf.lock.Lock()
	defer tf.lock.Unlock()

	err := tf.loadXdp()
	if err != nil {
		return err
	}

	err = tf.bpfObjs.NbWgProxySettingsMap.Put(mapKeyProxyPort, uint16(proxyPort))
	if err != nil {
		return err
	}

	err = tf.bpfObjs.NbWgProxySettingsMap.Put(mapKeyWgPort, uint16(wgPort))
	if err != nil {
		return err
	}

	tf.setFeatureFlag(featureFlagWGProxy)
	err = tf.bpfObjs.NbFeatures.Put(mapKeyFeatures, tf.featureFlags)
	if err != nil {
		return err
	}
	return nil
}

func (tf *GeneralManager) FreeWGProxy() error {
	log.Debugf("free ebpf WG proxy")
	return tf.unsetFeatureFlag(featureFlagWGProxy)
}
