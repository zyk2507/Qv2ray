#include "QvGeositeReader.hpp"

#define QV_MODULE_NAME "GeositeReader"

#ifndef ANDROID
#include "v2ray_geosite.pb.h"
// Recent protobuf versions pull in Abseil's LOG macro, which clashes with
// Qv2ray's own logging macro.  Restore the Qv2ray definition.
#ifdef LOG
#undef LOG
#endif
#define LOG(...) Qv2ray::base::log_internal<QV2RAY_LOG_NORMAL>(_LOG_ARG_(__VA_ARGS__))
#endif

namespace Qv2ray::components::geosite
{
    QMap<QString, QStringList> GeositeEntries;
    QStringList ReadGeoSiteFromFile(const QString &filepath)
    {
        if (GeositeEntries.contains(filepath))
        {
            return GeositeEntries.value(filepath);
        }
        else
        {
            QStringList list;
#ifndef ANDROID
            LOG("Reading geosites from: " + filepath);
            //
            GOOGLE_PROTOBUF_VERIFY_VERSION;
            //
            QFile f(filepath);
            bool opened = f.open(QFile::OpenModeFlag::ReadOnly);

            if (!opened)
            {
                LOG("File cannot be opened: " + filepath);
                return list;
            }

            auto content = f.readAll();
            f.close();
            //
            v2ray::core::app::router::GeoSiteList sites;
            sites.ParseFromArray(content.data(), content.size());

            for (const auto &e : sites.entry())
            {
                // We want to use lower string.
                list << QString::fromStdString(e.country_code()).toLower();
            }

            LOG("Loaded " + QSTRN(list.count()) + " geosite entries from data file.");
            // Optional:  Delete all global objects allocated by libprotobuf.
            google::protobuf::ShutdownProtobufLibrary();
#endif
            list.sort();
            GeositeEntries[filepath] = list;
            return list;
        }
    }
} // namespace Qv2ray::components::geosite
